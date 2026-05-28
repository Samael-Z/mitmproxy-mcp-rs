//! hudsucker MITM 代理：抓请求/响应配对落库、CA 生成/加载、start/stop、拦截改写。

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Result};
use bytes::Bytes;
use http_body_util::BodyExt;
use hudsucker::{
    certificate_authority::RcgenAuthority,
    hyper::{header, Request, Response, StatusCode},
    rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose},
    rustls::crypto::aws_lc_rs,
    Body, HttpContext, HttpHandler, Proxy, RequestOrResponse,
};
use regex::Regex;
use tokio::sync::Notify;

use crate::model::{FlowRow, Rule};
use crate::replay::SessionVars;
use crate::socks5;
use crate::store::Store;

static FLOW_COUNTER: AtomicU64 = AtomicU64::new(1);

fn now_secs() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

fn gen_id() -> String {
    let n = FLOW_COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{nanos:x}-{n}")
}

fn headers_vec(h: &header::HeaderMap) -> Vec<(String, String)> {
    h.iter()
        .map(|(k, v)| {
            (
                k.as_str().to_string(),
                String::from_utf8_lossy(v.as_bytes()).to_string(),
            )
        })
        .collect()
}

/// 由请求 parts 还原绝对 URL：
/// - absolute-form（普通 http 代理）直接用 uri；
/// - origin-form（TLS 隧道内）按 https + Host 头 + path 重建。
fn build_url(parts: &hudsucker::hyper::http::request::Parts) -> String {
    let uri = &parts.uri;
    if uri.scheme().is_some() {
        return uri.to_string();
    }
    let host = parts
        .headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .or_else(|| uri.authority().map(|a| a.as_str()))
        .unwrap_or("unknown");
    let pq = uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
    format!("https://{host}{pq}")
}

#[derive(Clone)]
struct PendingReq {
    id: String,
    url: String,
    host: String,
    method: String,
    headers: Vec<(String, String)>,
    body: Option<String>,
    ts: f64,
}

#[derive(Clone)]
pub struct CaptureHandler {
    store: Store,
    rules: Arc<Mutex<Vec<Rule>>>,
    scope: Arc<Mutex<Vec<String>>>,
    pending: VecDeque<PendingReq>,
}

impl CaptureHandler {
    fn rules_snapshot(&self) -> Vec<Rule> {
        self.rules.lock().unwrap().clone()
    }

    /// scope 为空表示抓全部；否则 host 需等于某域名或为其子域。
    fn in_scope(&self, host: &str) -> bool {
        let scope = self.scope.lock().unwrap();
        if scope.is_empty() {
            return true;
        }
        let h = host.to_lowercase();
        scope.iter().any(|d| {
            let d = d.trim_start_matches('.').to_lowercase();
            h == d || h.ends_with(&format!(".{d}"))
        })
    }
}

impl HttpHandler for CaptureHandler {
    async fn handle_request(
        &mut self,
        _ctx: &HttpContext,
        req: Request<Body>,
    ) -> RequestOrResponse {
        let (mut parts, body) = req.into_parts();
        tracing::debug!("handle_request {} {}", parts.method, parts.uri);
        // CONNECT 仅用于建立隧道，不是真实业务请求，直接转发不抓
        if parts.method == hudsucker::hyper::Method::CONNECT {
            return RequestOrResponse::Request(Request::from_parts(parts, body));
        }
        let raw = body
            .collect()
            .await
            .map(|c| c.to_bytes())
            .unwrap_or_else(|_| Bytes::new());
        let mut bytes = raw.to_vec();

        let url = build_url(&parts);
        let host = url::Url::parse(&url)
            .ok()
            .and_then(|u| u.host_str().map(|s| s.to_string()))
            .unwrap_or_default();

        // 请求阶段拦截规则
        for rule in self.rules_snapshot() {
            if rule.phase != "request" || !rule_matches(&rule, &url) {
                continue;
            }
            match rule.action.as_str() {
                "block" => {
                    let resp = Response::builder()
                        .status(StatusCode::FORBIDDEN)
                        .body(Body::from(Bytes::from_static(
                            b"blocked by mitmproxy-mcp-rs",
                        )))
                        .unwrap();
                    return RequestOrResponse::Response(resp);
                }
                "inject_header" => {
                    if let (Some(h), Some(v)) = (&rule.header, &rule.value) {
                        if let (Ok(name), Ok(val)) = (
                            header::HeaderName::from_bytes(h.as_bytes()),
                            header::HeaderValue::from_str(v),
                        ) {
                            parts.headers.insert(name, val);
                        }
                    }
                }
                "replace_body" => {
                    bytes = apply_replace(&bytes, &rule);
                }
                _ => {}
            }
        }

        let body_text = crate::bodies::safe_text(&bytes);
        let pending = PendingReq {
            id: gen_id(),
            url,
            host,
            method: parts.method.as_str().to_string(),
            headers: headers_vec(&parts.headers),
            body: body_text,
            ts: now_secs(),
        };
        self.pending.push_back(pending);

        let new_req = Request::from_parts(parts, Body::from(Bytes::from(bytes)));
        RequestOrResponse::Request(new_req)
    }

    async fn handle_response(&mut self, _ctx: &HttpContext, res: Response<Body>) -> Response<Body> {
        let (parts, body) = res.into_parts();
        let raw = body
            .collect()
            .await
            .map(|c| c.to_bytes())
            .unwrap_or_else(|_| Bytes::new());
        let mut bytes = raw.to_vec();

        let pending = self.pending.pop_front();

        // 响应阶段拦截规则
        if let Some(p) = &pending {
            for rule in self.rules_snapshot() {
                if rule.phase != "response" || !rule_matches(&rule, &p.url) {
                    continue;
                }
                if rule.action == "replace_body" {
                    bytes = apply_replace(&bytes, &rule);
                }
            }
        }

        if let Some(p) = pending {
            if !self.in_scope(&p.host) {
                return Response::from_parts(parts, Body::from(Bytes::from(bytes)));
            }
            let flow = FlowRow {
                id: p.id,
                seq: 0,
                url: p.url,
                host: p.host,
                method: p.method,
                status: Some(parts.status.as_u16() as i64),
                req_headers: p.headers,
                req_body: p.body,
                resp_headers: headers_vec(&parts.headers),
                resp_body: crate::bodies::safe_text(&bytes),
                timestamp: p.ts,
                size: bytes.len() as i64,
            };
            let _ = self.store.save_flow(&flow);
        }

        Response::from_parts(parts, Body::from(Bytes::from(bytes)))
    }
}

fn rule_matches(rule: &Rule, url: &str) -> bool {
    match &rule.url_match {
        Some(m) => url.contains(m.as_str()),
        None => true,
    }
}

fn apply_replace(bytes: &[u8], rule: &Rule) -> Vec<u8> {
    let (pat, rep) = match (&rule.pattern, &rule.replacement) {
        (Some(p), r) => (p, r.clone().unwrap_or_default()),
        _ => return bytes.to_vec(),
    };
    let text = match std::str::from_utf8(bytes) {
        Ok(t) => t,
        Err(_) => return bytes.to_vec(),
    };
    match Regex::new(pat) {
        Ok(re) => re.replace_all(text, rep.as_str()).into_owned().into_bytes(),
        Err(_) => bytes.to_vec(),
    }
}

/// 提前 bind 一次释放，给 Windows 保留段/被占等场景一个清晰中文错误。
fn precheck_bind(addr: SocketAddr, label: &str) -> Result<()> {
    match std::net::TcpListener::bind(addr) {
        Ok(l) => {
            drop(l);
            Ok(())
        }
        Err(e) => {
            let hint = if e.raw_os_error() == Some(10013) {
                format!(
                    "\n提示：端口 {} 可能落在 Windows 保留端口段（运行 `netsh interface ipv4 show excludedportrange protocol=tcp` 查看）。换一个不在保留段的端口。",
                    addr.port()
                )
            } else if e.raw_os_error() == Some(10048) {
                format!("\n提示：端口 {} 已被占用，换一个端口。", addr.port())
            } else {
                String::new()
            };
            Err(anyhow!("无法绑定 {label} {addr}: {e}{hint}"))
        }
    }
}

// ---------------------------------------------------------------------------
// 代理控制器
// ---------------------------------------------------------------------------
struct ProxyState {
    running: bool,
    host: String,
    port: u16,
    socks5_port: Option<u16>,
    /// 共享给 hudsucker 的 graceful shutdown future 和 SOCKS5 监听器 —— stop() 时
    /// 一次 notify_waiters 同时唤醒两边。
    shutdown: Option<Arc<Notify>>,
}

pub struct ProxyController {
    pub store: Store,
    pub rules: Arc<Mutex<Vec<Rule>>>,
    pub session: SessionVars,
    pub scope: Arc<Mutex<Vec<String>>>,
    ca_dir: PathBuf,
    state: Mutex<ProxyState>,
}

impl ProxyController {
    pub fn new(store: Store) -> Self {
        let ca_dir = dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".mitmproxy-mcp-rs");
        Self {
            store,
            rules: Arc::new(Mutex::new(Vec::new())),
            session: Arc::new(Mutex::new(HashMap::new())),
            scope: Arc::new(Mutex::new(Vec::new())),
            ca_dir,
            state: Mutex::new(ProxyState {
                running: false,
                host: "127.0.0.1".into(),
                port: 18080,
                socks5_port: None,
                shutdown: None,
            }),
        }
    }

    pub fn ca_cert_path(&self) -> PathBuf {
        self.ca_dir.join("ca-cert.pem")
    }

    /// 生成或加载 CA，返回 RcgenAuthority。
    fn load_ca(&self) -> Result<RcgenAuthority> {
        std::fs::create_dir_all(&self.ca_dir)?;
        let cert_path = self.ca_dir.join("ca-cert.pem");
        let key_path = self.ca_dir.join("ca-key.pem");

        let (cert_pem, key_pem) = if cert_path.exists() && key_path.exists() {
            (
                std::fs::read_to_string(&cert_path)?,
                std::fs::read_to_string(&key_path)?,
            )
        } else {
            let mut params = CertificateParams::default();
            params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            params
                .distinguished_name
                .push(DnType::CommonName, "mitmproxy-mcp-rs CA");
            params
                .distinguished_name
                .push(DnType::OrganizationName, "mitmproxy-mcp-rs");
            params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
            let key_pair = KeyPair::generate()?;
            let cert = params.self_signed(&key_pair)?;
            let cert_pem = cert.pem();
            let key_pem = key_pair.serialize_pem();
            std::fs::write(&cert_path, &cert_pem)?;
            std::fs::write(&key_path, &key_pem)?;
            (cert_pem, key_pem)
        };

        let key_pair = KeyPair::from_pem(&key_pem)?;
        let issuer = Issuer::from_ca_cert_pem(&cert_pem, key_pair)
            .map_err(|e| anyhow!("加载 CA 失败: {e}"))?;
        Ok(RcgenAuthority::new(
            issuer,
            1_000,
            aws_lc_rs::default_provider(),
        ))
    }

    pub fn start(&self, port: u16, host: &str, socks5_port: Option<u16>) -> Result<String> {
        {
            let st = self.state.lock().unwrap();
            if st.running {
                return Ok(format!("代理已在运行：{}:{}", st.host, st.port));
            }
        }
        let addr: SocketAddr = format!("{host}:{port}")
            .parse()
            .map_err(|e| anyhow!("地址解析失败: {e}"))?;
        precheck_bind(addr, "HTTP")?;

        let socks5_addr = match socks5_port {
            Some(p) => {
                let a: SocketAddr = format!("{host}:{p}")
                    .parse()
                    .map_err(|e| anyhow!("SOCKS5 地址解析失败: {e}"))?;
                precheck_bind(a, "SOCKS5")?;
                Some(a)
            }
            None => None,
        };

        let ca = self.load_ca()?;

        let handler = CaptureHandler {
            store: self.store.clone(),
            rules: self.rules.clone(),
            scope: self.scope.clone(),
            pending: VecDeque::new(),
        };

        let shutdown = Arc::new(Notify::new());

        let sd_http = shutdown.clone();
        let proxy = Proxy::builder()
            .with_addr(addr)
            .with_ca(ca)
            .with_rustls_connector(aws_lc_rs::default_provider())
            .with_http_handler(handler)
            .with_graceful_shutdown(async move {
                sd_http.notified().await;
            })
            .build()
            .map_err(|e| anyhow!("构建代理失败: {e}"))?;

        tokio::spawn(async move {
            if let Err(e) = proxy.start().await {
                tracing::error!("proxy exited: {e:?}");
            }
        });

        // SOCKS5 桥接：内部连到 127.0.0.1:port（不管 host 绑哪）。
        if let Some(sa) = socks5_addr {
            let http_loopback: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
            let sd_socks = shutdown.clone();
            tokio::spawn(async move {
                if let Err(e) = socks5::run(sa, http_loopback, sd_socks).await {
                    tracing::error!("socks5 listener exited: {e:?}");
                }
            });
        }

        {
            let mut st = self.state.lock().unwrap();
            st.running = true;
            st.host = host.to_string();
            st.port = port;
            st.socks5_port = socks5_port;
            st.shutdown = Some(shutdown);
        }

        let cert = self.ca_cert_path();
        let socks_line = match socks5_port {
            Some(p) => {
                format!("\n- SOCKS5 入口：{host}:{p}（appproxy/tun2socks 可直接用 socks5 协议）")
            }
            None => String::new(),
        };
        Ok(format!(
            "代理已启动：{host}:{port}\n- 客户端把 HTTP/HTTPS 代理指向此地址即可抓包。{socks_line}\n- HTTPS 需在客户端/手机安装 CA 证书：{}",
            cert.display()
        ))
    }

    pub fn stop(&self) -> String {
        let mut st = self.state.lock().unwrap();
        if !st.running {
            return "代理当前未运行。".into();
        }
        if let Some(sd) = st.shutdown.take() {
            sd.notify_waiters();
        }
        st.running = false;
        st.socks5_port = None;
        "代理已停止。".into()
    }

    pub fn status(&self) -> serde_json::Value {
        let st = self.state.lock().unwrap();
        serde_json::json!({
            "running": st.running,
            "host": st.host,
            "port": st.port,
            "socks5_port": st.socks5_port,
            "scope": *self.scope.lock().unwrap(),
            "captured": self.store.count(),
            "session_vars": self.session.lock().unwrap().keys().cloned().collect::<Vec<_>>(),
            "rules": self.rules.lock().unwrap().len(),
            "ca_cert": self.ca_cert_path().display().to_string(),
        })
    }
}
