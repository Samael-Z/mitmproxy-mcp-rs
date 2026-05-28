//! 跨模块共享的数据结构。

use serde::{Deserialize, Serialize};

/// 一条抓到的 HTTP flow（与 SQLite 行一一对应）。
/// headers 保留原始顺序与重复键（HTTP 指纹逆向需要）。
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FlowRow {
    pub id: String,
    pub seq: i64,
    pub url: String,
    pub host: String,
    pub method: String,
    pub status: Option<i64>,
    pub req_headers: Vec<(String, String)>,
    pub req_body: Option<String>,
    pub resp_headers: Vec<(String, String)>,
    pub resp_body: Option<String>,
    pub timestamp: f64,
    pub size: i64,
}

impl FlowRow {
    /// 折叠 header 为 map（重复键后者覆盖），用于一般展示/查找。
    pub fn req_header_map(&self) -> std::collections::HashMap<String, String> {
        self.req_headers.iter().cloned().collect()
    }

    pub fn content_type(&self) -> String {
        for (k, v) in &self.resp_headers {
            if k.eq_ignore_ascii_case("content-type") {
                return v.split(';').next().unwrap_or("").trim().to_string();
            }
        }
        String::new()
    }
}

/// 拦截/改写规则。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub rule_id: String,
    pub action: String, // block | replace_body | inject_header
    pub phase: String,  // request | response
    pub url_match: Option<String>,
    pub header: Option<String>,
    pub value: Option<String>,
    pub pattern: Option<String>,
    pub replacement: Option<String>,
}
