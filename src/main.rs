//! 命令行版 mitmproxy MCP server（Rust）。
//!
//! 链路：appproxy(手机转发) -> 本工具(PC 端 hudsucker MITM 抓包+分析) -> MCP(stdio)。
//! 代理默认不自动启动、绑回环；由 AI 调用 start_proxy 工具启动（默认端口 9876）。

mod analysis;
mod bodies;
mod codec;
mod codegen;
mod model;
mod proxy;
mod replay;
mod server;
mod store;

use std::sync::Arc;

use clap::Parser;
use rmcp::{transport::stdio, ServiceExt};

use proxy::ProxyController;
use server::Server;
use store::Store;

#[derive(Parser, Debug)]
#[command(
    name = "mitmproxy-mcp-rs",
    about = "mitmproxy 抓包 + 签名逆向分析 MCP server"
)]
struct Cli {
    /// SQLite 抓包库路径
    #[arg(long, default_value = "mitm_re_traffic.db")]
    db: String,

    /// 抓包白名单域名，逗号分隔（默认抓全部）
    #[arg(long, default_value = "")]
    scope: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 日志输出到 stderr，避免污染 stdio 上的 MCP 协议
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
        )
        .init();

    let cli = Cli::parse();

    let store = Store::open(&cli.db)?;
    let ctl = Arc::new(ProxyController::new(store));
    let initial_scope: Vec<String> = cli
        .scope
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if !initial_scope.is_empty() {
        *ctl.scope.lock().unwrap() = initial_scope;
    }

    let service = Server::new(ctl).serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}
