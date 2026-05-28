//! 重放：用 reqwest(rustls) 重发抓到的请求，支持 method/headers/body/query 覆盖与 session 变量。

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use reqwest::Method;
use serde_json::{json, Value};
use url::Url;

use crate::store::Store;

const DROP_REPLAY_HEADERS: &[&str] = &[
    "host", "content-length", "content-encoding", "connection", "proxy-connection",
    "transfer-encoding", "accept-encoding",
];

pub type SessionVars = Arc<Mutex<HashMap<String, String>>>;

fn apply_vars(text: &str, vars: &HashMap<String, String>) -> String {
    let mut out = text.to_string();
    for (k, v) in vars {
        out = out.replace(&format!("${{{k}}}"), v);
    }
    out
}

pub async fn replay(
    store: &Store,
    session: &SessionVars,
    flow_id: &str,
    method: Option<String>,
    headers: Option<HashMap<String, String>>,
    body: Option<String>,
    query_overrides: Option<HashMap<String, String>>,
    timeout_secs: f64,
) -> Value {
    let f = match store.get(flow_id) {
        Some(f) => f,
        None => return json!({"error": format!("未找到 flow: {flow_id}")}),
    };
    let vars = session.lock().unwrap().clone();

    // URL + query 覆盖
    let mut url = match Url::parse(&f.url) {
        Ok(u) => u,
        Err(e) => return json!({"error": format!("URL 解析失败: {e}")}),
    };
    if let Some(over) = &query_overrides {
        let existing: Vec<(String, String)> = url
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        let mut merged: Vec<(String, String)> = existing;
        for (k, v) in over {
            if let Some(slot) = merged.iter_mut().find(|(ek, _)| ek == k) {
                slot.1 = v.clone();
            } else {
                merged.push((k.clone(), v.clone()));
            }
        }
        url.query_pairs_mut().clear().extend_pairs(merged);
    }

    let method_str = method.unwrap_or_else(|| f.method.clone()).to_uppercase();
    let m = Method::from_bytes(method_str.as_bytes()).unwrap_or(Method::GET);

    // headers
    let mut hdr_map: Vec<(String, String)> = f
        .req_headers
        .iter()
        .filter(|(k, _)| !DROP_REPLAY_HEADERS.contains(&k.to_lowercase().as_str()))
        .map(|(k, v)| (k.clone(), apply_vars(v, &vars)))
        .collect();
    if let Some(over) = headers {
        for (k, v) in over {
            let v = apply_vars(&v, &vars);
            if let Some(slot) = hdr_map.iter_mut().find(|(ek, _)| ek.eq_ignore_ascii_case(&k)) {
                slot.1 = v;
            } else {
                hdr_map.push((k, v));
            }
        }
    }

    let content = match body {
        Some(b) => Some(apply_vars(&b, &vars)),
        None => f.req_body.clone().map(|b| apply_vars(&b, &vars)),
    };

    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs_f64(timeout_secs))
        .danger_accept_invalid_certs(true) // 重放目标常是被 MITM 的接口
        .build()
    {
        Ok(c) => c,
        Err(e) => return json!({"error": format!("client 构建失败: {e}")}),
    };

    let mut req = client.request(m, url.clone());
    for (k, v) in &hdr_map {
        req = req.header(k, v);
    }
    if let Some(c) = &content {
        req = req.body(c.clone());
    }

    match req.send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let resp_headers: HashMap<String, String> = resp
                .headers()
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
                .collect();
            let text = resp.text().await.unwrap_or_default();
            let preview: String = text.chars().take(2000).collect();
            json!({
                "request": {"method": method_str, "url": url.as_str()},
                "status": status,
                "response_headers": resp_headers,
                "body_preview": preview,
                "body_len": text.len(),
            })
        }
        Err(e) => json!({
            "error": format!("replay 失败: {e}"),
            "request": {"method": method_str, "url": url.as_str()},
        }),
    }
}
