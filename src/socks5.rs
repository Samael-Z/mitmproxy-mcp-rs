//! SOCKS5 前置桥接：把 SOCKS5 入站 CONNECT 合成 HTTP CONNECT 喂给 hudsucker。
//!
//! 设计要点：
//! - 不动 hudsucker，只在它前面摆一个翻译器。共享同一份 CA、capture handler、store。
//! - 对 HTTPS（任何 TLS 端口）：hudsucker 在合成 CONNECT 后照常 MITM，捕获完整请求/响应。
//! - 对纯 HTTP via SOCKS5：hudsucker 把 CONNECT 当透明隧道转发，不解析内容（已知局限，
//!   现代 app 几乎清一色 HTTPS，可接受）。
//!
//! 协议参考：RFC 1928。本实现仅支持无认证 + CONNECT 命令（appproxy/tun2socks 用的就是这两样）。

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;

/// 启动 SOCKS5 监听器，桥接到 `http_proxy_addr`（hudsucker 的 HTTP 端口）。
/// 收到 `shutdown.notify_waiters()` 后优雅退出。
pub async fn run(
    addr: SocketAddr,
    http_proxy_addr: SocketAddr,
    shutdown: Arc<Notify>,
) -> Result<()> {
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("bind SOCKS5 {addr}"))?;
    tracing::info!("SOCKS5 listening on {addr}");

    loop {
        tokio::select! {
            _ = shutdown.notified() => {
                tracing::info!("SOCKS5 shutting down");
                return Ok(());
            }
            res = listener.accept() => {
                let (stream, _peer) = match res {
                    Ok(t) => t,
                    Err(e) => {
                        tracing::warn!("SOCKS5 accept error: {e}");
                        continue;
                    }
                };
                tokio::spawn(async move {
                    if let Err(e) = handle_conn(stream, http_proxy_addr).await {
                        tracing::debug!("SOCKS5 conn ended: {e}");
                    }
                });
            }
        }
    }
}

async fn handle_conn(mut client: TcpStream, http_addr: SocketAddr) -> Result<()> {
    // ---- 1) Greeting：VER + NMETHODS + METHODS[] ----
    let mut hdr = [0u8; 2];
    client.read_exact(&mut hdr).await?;
    if hdr[0] != 0x05 {
        return Err(anyhow!("not SOCKS5 (ver=0x{:02x})", hdr[0]));
    }
    let nmethods = hdr[1] as usize;
    let mut methods = vec![0u8; nmethods];
    if nmethods > 0 {
        client.read_exact(&mut methods).await?;
    }
    // 回复：选 0x00 (NO AUTH)。我们不验证客户端，本地工具用。
    client.write_all(&[0x05, 0x00]).await?;

    // ---- 2) Request：VER + CMD + RSV + ATYP + ADDR + PORT ----
    let mut head = [0u8; 4];
    client.read_exact(&mut head).await?;
    if head[0] != 0x05 {
        return Err(anyhow!("bad request ver"));
    }
    if head[1] != 0x01 {
        // 只支持 CONNECT (0x01)，其他（BIND/UDP ASSOC）回 0x07 命令不支持
        let _ = client
            .write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await;
        return Err(anyhow!("only CONNECT supported (cmd=0x{:02x})", head[1]));
    }

    let host = match head[3] {
        0x01 => {
            // IPv4
            let mut o = [0u8; 4];
            client.read_exact(&mut o).await?;
            format!("{}.{}.{}.{}", o[0], o[1], o[2], o[3])
        }
        0x03 => {
            // domain: 1-byte len + name
            let mut len_buf = [0u8; 1];
            client.read_exact(&mut len_buf).await?;
            let mut name = vec![0u8; len_buf[0] as usize];
            client.read_exact(&mut name).await?;
            String::from_utf8(name).context("invalid SOCKS5 domain")?
        }
        0x04 => {
            // IPv6
            let mut b = [0u8; 16];
            client.read_exact(&mut b).await?;
            std::net::Ipv6Addr::from(b).to_string()
        }
        _ => {
            let _ = client
                .write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await;
            return Err(anyhow!("bad ATYP 0x{:02x}", head[3]));
        }
    };
    let mut port_b = [0u8; 2];
    client.read_exact(&mut port_b).await?;
    let port = u16::from_be_bytes(port_b);
    let target = format!("{host}:{port}");

    // ---- 3) 回复 success ----
    // BND.ADDR/PORT 写 0.0.0.0:0；多数客户端（含 tun2socks/curl）忽略。
    client
        .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;

    // ---- 4) 内部连到 hudsucker HTTP 端口，合成 CONNECT ----
    let mut upstream = TcpStream::connect(http_addr)
        .await
        .with_context(|| format!("connect to HTTP proxy {http_addr}"))?;
    let req = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n");
    upstream.write_all(req.as_bytes()).await?;

    // ---- 5) 吃掉 hudsucker 返的 "HTTP/1.1 200 ..."，直到 \r\n\r\n ----
    let mut resp_hdr = Vec::with_capacity(128);
    let mut byte = [0u8; 1];
    loop {
        let n = upstream.read(&mut byte).await?;
        if n == 0 {
            return Err(anyhow!("upstream closed before CONNECT response"));
        }
        resp_hdr.push(byte[0]);
        if resp_hdr.len() >= 4 && resp_hdr.ends_with(b"\r\n\r\n") {
            break;
        }
        if resp_hdr.len() > 8192 {
            return Err(anyhow!("CONNECT response header too large"));
        }
    }
    if !(resp_hdr.starts_with(b"HTTP/1.1 2") || resp_hdr.starts_with(b"HTTP/1.0 2")) {
        return Err(anyhow!(
            "upstream CONNECT not 2xx: {}",
            String::from_utf8_lossy(&resp_hdr)
                .lines()
                .next()
                .unwrap_or("?")
        ));
    }

    // ---- 6) 隧道模式：两个 socket 互相 splice，hudsucker 在另一端做 MITM ----
    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
    Ok(())
}
