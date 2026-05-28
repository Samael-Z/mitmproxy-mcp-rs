//! 从抓到的 flow 生成 curl 命令 / Python 客户端脚手架。

use crate::model::FlowRow;

const DROP_HEADERS: &[&str] = &[
    "content-length",
    "connection",
    "proxy-connection",
    "transfer-encoding",
];

fn req_headers(f: &FlowRow) -> Vec<(String, String)> {
    f.req_headers
        .iter()
        .filter(|(k, _)| !DROP_HEADERS.contains(&k.to_lowercase().as_str()))
        .cloned()
        .collect()
}

fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

pub fn to_curl(f: &FlowRow) -> String {
    let mut parts = vec![
        "curl".to_string(),
        "-X".into(),
        f.method.clone(),
        sh_quote(&f.url),
    ];
    for (k, v) in req_headers(f) {
        parts.push("-H".into());
        parts.push(sh_quote(&format!("{k}: {v}")));
    }
    if let Some(b) = &f.req_body {
        parts.push("--data-raw".into());
        parts.push(sh_quote(b));
    }
    parts.join(" ")
}

fn py_str(s: &str) -> String {
    // 用 repr 风格：转义反斜杠/单引号/换行
    let escaped = s
        .replace('\\', "\\\\")
        .replace('\'', "\\'")
        .replace('\n', "\\n")
        .replace('\r', "\\r");
    format!("'{escaped}'")
}

pub fn to_python(f: &FlowRow, framework: &str) -> String {
    let headers = req_headers(f);
    let hdr_lines = headers
        .iter()
        .map(|(k, v)| format!("    {}: {}", py_str(k), py_str(v)))
        .collect::<Vec<_>>()
        .join(",\n");
    let method = f.method.to_lowercase();
    let has_body = f.req_body.is_some();

    let mut lines: Vec<String> = Vec::new();
    if framework == "curl_cffi" {
        lines.push("from curl_cffi import requests".into());
    } else {
        lines.push("import requests".into());
    }
    lines.push(String::new());
    lines.push("headers = {".into());
    lines.push(hdr_lines);
    lines.push("}".into());
    if let Some(b) = &f.req_body {
        lines.push(format!("data = {}", py_str(b)));
    }
    lines.push(String::new());

    let imp = if framework == "curl_cffi" {
        ", impersonate=\"chrome\""
    } else {
        ""
    };
    let data_arg = if has_body { ", data=data" } else { "" };
    lines.push(format!(
        "resp = requests.{method}({}, headers=headers{data_arg}{imp})",
        py_str(&f.url)
    ));
    lines.push("print(resp.status_code)".into());
    lines.push("print(resp.text)".into());
    lines.join("\n")
}
