//! 编解码 + 加密特征启发式（逆向核心能力）。
//!
//! - `classify`: 判断字符串"长得像什么"（md5/sha/hmac/base64/jwt/时间戳/uuid/...），定位签名/加密字段。
//! - `decode_value`: 自动/链式解码（base64/base64url/hex/url/gzip/zlib/jwt）。

use std::sync::LazyLock;

use base64::Engine;
use flate2::read::{GzDecoder, ZlibDecoder};
use regex::Regex;
use serde::Serialize;
use serde_json::{json, Value};
use std::io::Read;

static RE_HEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[0-9a-fA-F]+$").unwrap());
static RE_B64: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z0-9+/]+={0,2}$").unwrap());
static RE_B64URL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z0-9_-]+={0,2}$").unwrap());
static RE_UUID: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
        .unwrap()
});
static RE_JWT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$").unwrap());
static RE_PCT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"%[0-9a-fA-F]{2}").unwrap());

const TS_S_MIN: i64 = 1_000_000_000;
const TS_S_MAX: i64 = 2_000_000_000;
const TS_MS_MIN: i64 = 1_000_000_000_000;
const TS_MS_MAX: i64 = 2_000_000_000_000;

fn hex_hash_family(n: usize) -> Option<&'static str> {
    match n {
        32 => Some("md5"),
        40 => Some("sha1"),
        56 => Some("sha224"),
        64 => Some("sha256"),
        96 => Some("sha384"),
        128 => Some("sha512"),
        _ => None,
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Classification {
    pub tags: Vec<String>,
    pub signature_suspect: bool,
    pub note: String,
}

pub fn classify(value: &str) -> Classification {
    let v = value.trim();
    let n = v.len();
    let mut tags: Vec<String> = Vec::new();
    let mut notes: Vec<String> = Vec::new();

    if v.is_empty() {
        return Classification {
            tags: vec!["empty".into()],
            signature_suspect: false,
            note: String::new(),
        };
    }

    // JWT 优先
    if RE_JWT.is_match(v) && v.matches('.').count() == 2 {
        tags.push("jwt".into());
        notes.push("JWT (header.payload.signature)".into());
    }

    // 纯数字 -> 时间戳/序号
    let is_digits = !v.is_empty() && v.trim_start_matches('-').chars().all(|c| c.is_ascii_digit());
    if is_digits {
        tags.push("numeric".into());
        if let Ok(iv) = v.parse::<i64>() {
            if (TS_MS_MIN..=TS_MS_MAX).contains(&iv) {
                tags.push("timestamp_ms".into());
                notes.push(format!("unix ms -> {}", fmt_ts(iv / 1000)));
            } else if (TS_S_MIN..=TS_S_MAX).contains(&iv) {
                tags.push("timestamp_s".into());
                notes.push(format!("unix s -> {}", fmt_ts(iv)));
            }
        }
    }

    // UUID
    if RE_UUID.is_match(v) {
        tags.push("uuid".into());
        notes.push("UUID / 可能是 nonce/deviceId".into());
    }

    // 定长 hex -> 哈希家族
    let has_jwt = tags.iter().any(|t| t == "jwt");
    if !has_jwt && RE_HEX.is_match(v) {
        if let Some(fam) = hex_hash_family(n) {
            tags.push(format!("hex:{fam}"));
            notes.push(format!("{n} hex chars -> 可能是 {fam}/HMAC-{fam}"));
        } else if n >= 16 && n % 2 == 0 {
            tags.push("hex".into());
            notes.push(format!("{n} hex chars"));
        }
    }

    // base64 / base64url
    if !has_jwt && n >= 8 && n % 4 == 0 && !is_digits {
        if RE_B64.is_match(v) && (v.contains('+') || v.contains('/') || v.ends_with('=') || !RE_HEX.is_match(v)) {
            if let Some(raw) = try_b64(v, false) {
                tags.push("base64".into());
                notes.push(describe_bytes("base64 decoded", &raw));
            }
        } else if RE_B64URL.is_match(v) && (v.contains('-') || v.contains('_')) {
            if let Some(raw) = try_b64(v, true) {
                tags.push("base64url".into());
                notes.push(describe_bytes("base64url decoded", &raw));
            }
        }
    }

    // URL-encoded
    if v.contains('%') && RE_PCT.is_match(v) {
        tags.push("url_encoded".into());
    }

    if tags.is_empty() {
        tags.push("text".into());
    }

    let temporal = tags
        .iter()
        .any(|t| t == "uuid" || t == "timestamp_ms" || t == "timestamp_s");
    let suspect = tags.iter().any(|t| {
        t.starts_with("hex:") || t == "hex" || t == "base64" || t == "base64url" || t == "jwt"
    }) && !temporal;

    Classification {
        tags,
        signature_suspect: suspect,
        note: notes.join("; "),
    }
}

/// 对"是签名/加密字段"的可疑度打分，用于排序。
pub fn suspect_score(key: &str, info: &Classification) -> i32 {
    let mut score = 0;
    if info.signature_suspect {
        score += 5;
    }
    let key_l = key.to_lowercase();
    for (kw, w) in [
        ("sign", 6), ("sig", 4), ("token", 3), ("hmac", 6), ("mac", 2),
        ("hash", 4), ("digest", 4), ("secret", 4), ("auth", 2),
        ("nonce", 2), ("salt", 2), ("encrypt", 4), ("cipher", 4),
    ] {
        if key_l.contains(kw) {
            score += w;
        }
    }
    if info.tags.iter().any(|t| t.starts_with("hex:")) {
        score += 3;
    }
    if info.tags.iter().any(|t| t == "jwt") {
        score += 2;
    }
    score
}

// ---------------------------------------------------------------------------
// 解码
// ---------------------------------------------------------------------------
pub fn decode_value(value: &str, chain: Option<Vec<String>>) -> Value {
    if let Some(steps) = chain {
        let mut cur = StepVal::Text(value.to_string());
        let mut log: Vec<Value> = Vec::new();
        for step in &steps {
            let (next, ok, detail) = decode_step(&cur, step);
            log.push(json!({"step": step, "ok": ok, "detail": detail}));
            cur = next;
            if !ok {
                break;
            }
        }
        return json!({"input": value, "chain": log, "result": cur.into_json()});
    }

    // 自动模式
    let cls = classify(value);
    let mut attempts: Vec<Value> = Vec::new();
    for step in auto_steps(&cls.tags) {
        let (out, ok, detail) = decode_step(&StepVal::Text(value.to_string()), &step);
        if ok {
            attempts.push(json!({"method": step, "result": out.into_json(), "detail": detail}));
        }
    }
    if attempts.is_empty() {
        attempts.push(json!({"method": "none", "result": value, "detail": "no decoding matched"}));
    }
    json!({
        "input": value,
        "classification": cls,
        "decodings": attempts,
    })
}

fn auto_steps(tags: &[String]) -> Vec<String> {
    let mut steps = Vec::new();
    if tags.iter().any(|t| t == "jwt") {
        steps.push("jwt".into());
    }
    if tags.iter().any(|t| t == "base64") {
        steps.push("base64".into());
    }
    if tags.iter().any(|t| t == "base64url") {
        steps.push("base64url".into());
    }
    if tags.iter().any(|t| t == "hex" || t.starts_with("hex:")) {
        steps.push("hex".into());
    }
    if tags.iter().any(|t| t == "url_encoded") {
        steps.push("url".into());
    }
    if steps.is_empty() {
        steps = vec!["base64".into(), "hex".into(), "url".into()];
    }
    steps
}

enum StepVal {
    Text(String),
    Bytes(Vec<u8>),
    Json(Value),
}

impl StepVal {
    fn as_string(&self) -> String {
        match self {
            StepVal::Text(s) => s.clone(),
            StepVal::Bytes(b) => String::from_utf8_lossy(b).to_string(),
            StepVal::Json(v) => v.to_string(),
        }
    }
    fn as_bytes(&self) -> Vec<u8> {
        match self {
            StepVal::Text(s) => s.as_bytes().to_vec(),
            StepVal::Bytes(b) => b.clone(),
            StepVal::Json(v) => v.to_string().into_bytes(),
        }
    }
    fn into_json(self) -> Value {
        match self {
            StepVal::Text(s) => Value::String(s),
            StepVal::Json(v) => v,
            StepVal::Bytes(b) => match String::from_utf8(b.clone()) {
                Ok(s) => Value::String(s),
                Err(_) => Value::String(describe_bytes("", &b)),
            },
        }
    }
}

fn decode_step(value: &StepVal, step: &str) -> (StepVal, bool, String) {
    match step {
        "base64" => match try_b64(&value.as_string(), false) {
            Some(raw) => {
                let d = describe_bytes("", &raw);
                (StepVal::Bytes(raw), true, d)
            }
            None => (StepVal::Text(value.as_string()), false, "decode failed".into()),
        },
        "base64url" => match try_b64(&value.as_string(), true) {
            Some(raw) => {
                let d = describe_bytes("", &raw);
                (StepVal::Bytes(raw), true, d)
            }
            None => (StepVal::Text(value.as_string()), false, "decode failed".into()),
        },
        "hex" => match hex::decode(value.as_string().trim()) {
            Ok(raw) => {
                let d = describe_bytes("", &raw);
                (StepVal::Bytes(raw), true, d)
            }
            Err(e) => (StepVal::Text(value.as_string()), false, format!("hex failed: {e}")),
        },
        "url" => (
            StepVal::Text(
                percent_encoding::percent_decode_str(&value.as_string())
                    .decode_utf8_lossy()
                    .replace('+', " "),
            ),
            true,
            "url-decoded".into(),
        ),
        "gzip" => match gunzip(&value.as_bytes()) {
            Ok(raw) => {
                let d = describe_bytes("", &raw);
                (StepVal::Bytes(raw), true, d)
            }
            Err(e) => (StepVal::Text(value.as_string()), false, format!("gzip failed: {e}")),
        },
        "zlib" => match zlib_inflate(&value.as_bytes()) {
            Ok(raw) => {
                let d = describe_bytes("", &raw);
                (StepVal::Bytes(raw), true, d)
            }
            Err(e) => (StepVal::Text(value.as_string()), false, format!("zlib failed: {e}")),
        },
        "jwt" => (StepVal::Json(decode_jwt(&value.as_string())), true, "jwt header+payload".into()),
        other => (StepVal::Text(value.as_string()), false, format!("unknown step: {other}")),
    }
}

fn decode_jwt(token: &str) -> Value {
    let parts: Vec<&str> = token.split('.').collect();
    let mut out = serde_json::Map::new();
    for (name, idx) in [("header", 0usize), ("payload", 1usize)] {
        if let Some(part) = parts.get(idx) {
            if let Some(raw) = try_b64(part, true) {
                match serde_json::from_slice::<Value>(&raw) {
                    Ok(v) => {
                        out.insert(name.into(), v);
                    }
                    Err(_) => {
                        out.insert(name.into(), Value::String(String::from_utf8_lossy(&raw).to_string()));
                    }
                }
            }
        }
    }
    out.insert(
        "signature_present".into(),
        Value::Bool(parts.len() == 3 && !parts[2].is_empty()),
    );
    Value::Object(out)
}

// ---------------------------------------------------------------------------
// 辅助
// ---------------------------------------------------------------------------
fn try_b64(s: &str, url: bool) -> Option<Vec<u8>> {
    let s = s.trim();
    let pad = (4 - s.len() % 4) % 4;
    let padded = format!("{}{}", s, "=".repeat(pad));
    let res = if url {
        base64::engine::general_purpose::URL_SAFE.decode(padded.as_bytes())
    } else {
        base64::engine::general_purpose::STANDARD.decode(padded.as_bytes())
    };
    match res {
        Ok(raw) if !raw.is_empty() => Some(raw),
        _ => None,
    }
}

fn gunzip(data: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut d = GzDecoder::new(data);
    let mut out = Vec::new();
    d.read_to_end(&mut out)?;
    Ok(out)
}

fn zlib_inflate(data: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut d = ZlibDecoder::new(data);
    let mut out = Vec::new();
    d.read_to_end(&mut out)?;
    Ok(out)
}

fn describe_bytes(prefix: &str, raw: &[u8]) -> String {
    let head = if prefix.is_empty() {
        String::new()
    } else {
        format!("{prefix}: ")
    };
    if let Ok(txt) = std::str::from_utf8(raw) {
        let printable = txt
            .chars()
            .take(64)
            .all(|c| c as u32 > 31 || c == '\r' || c == '\n' || c == '\t');
        if printable {
            let snippet: String = txt.chars().take(120).collect();
            return format!("{head}utf-8 text: \"{snippet}\"");
        }
    }
    let magic = magic(raw).map(|m| format!(", looks like {m}")).unwrap_or_default();
    let hexhead = hex::encode(&raw[..raw.len().min(16)]);
    format!("{head}{} bytes{magic}, hex={hexhead}", raw.len())
}

fn magic(raw: &[u8]) -> Option<&'static str> {
    if raw.len() >= 2 && raw[0] == 0x1f && raw[1] == 0x8b {
        return Some("gzip");
    }
    if raw.len() >= 2 && raw[0] == 0x78 && matches!(raw[1], 0x9c | 0x01 | 0xda) {
        return Some("zlib");
    }
    if raw.len() >= 4 && &raw[..4] == b"PK\x03\x04" {
        return Some("zip");
    }
    if raw.len() > 2 && raw[0] == 0x08 {
        return Some("protobuf?(field1 varint)");
    }
    None
}

fn fmt_ts(epoch: i64) -> String {
    // 不引 chrono：用简单的 UTC 转换展示
    let days = epoch / 86400;
    let secs = epoch % 86400;
    let (h, m, s) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    // 1970-01-01 起的天数 -> 年月日
    let mut y = 1970i64;
    let mut d = days;
    loop {
        let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
        let yd = if leap { 366 } else { 365 };
        if d >= yd {
            d -= yd;
            y += 1;
        } else {
            break;
        }
    }
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let mdays = [31, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut mon = 0usize;
    while mon < 12 && d >= mdays[mon] {
        d -= mdays[mon];
        mon += 1;
    }
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
        y,
        mon + 1,
        d + 1,
        h,
        m,
        s
    )
}
