//! 逆向分析：参数拆解、双请求 diff、跨请求参数追踪、API 聚类、认证识别。

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::LazyLock;

use regex::Regex;
use serde_json::{json, Value};
use url::Url;

use crate::bodies::parse_json_body;
use crate::codec::{self, Classification};
use crate::model::FlowRow;

const SKIP_HEADERS: &[&str] = &[
    "host",
    "content-length",
    "accept",
    "accept-encoding",
    "accept-language",
    "connection",
    "user-agent",
    "content-type",
    "cache-control",
    "pragma",
];

static RE_NUM_SEG: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\d+$").unwrap());
static RE_HEX_SEG: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[0-9a-fA-F]{8,}$").unwrap());

// ---------------------------------------------------------------------------
// 参数拆解
// ---------------------------------------------------------------------------
fn flatten_json(v: &Value, prefix: &str, out: &mut Vec<(String, String)>) {
    match v {
        Value::Object(map) => {
            for (k, val) in map {
                let key = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{prefix}.{k}")
                };
                flatten_json(val, &key, out);
            }
        }
        Value::Array(arr) => {
            for (i, val) in arr.iter().enumerate() {
                flatten_json(val, &format!("{prefix}[{i}]"), out);
            }
        }
        Value::Null => out.push((prefix.to_string(), String::new())),
        Value::String(s) => out.push((prefix.to_string(), s.clone())),
        other => out.push((prefix.to_string(), other.to_string())),
    }
}

pub struct Params {
    pub query: Vec<(String, String)>,
    pub body: Vec<(String, String)>,
    pub header: Vec<(String, String)>,
}

pub fn extract_params(f: &FlowRow) -> Params {
    let mut query = Vec::new();
    if let Ok(u) = Url::parse(&f.url) {
        for (k, v) in u.query_pairs() {
            query.push((k.into_owned(), v.into_owned()));
        }
    }

    let mut body = Vec::new();
    if let Some(b) = f.req_body.as_deref() {
        if let Some(js) = parse_json_body(Some(b)) {
            flatten_json(&js, "", &mut body);
        } else if b.contains('=') {
            // 当作 x-www-form-urlencoded
            for pair in b.split('&') {
                let mut it = pair.splitn(2, '=');
                let k = it.next().unwrap_or("").to_string();
                let v = it.next().unwrap_or("").to_string();
                body.push((k, v));
            }
        } else {
            body.push(("<raw>".into(), b.to_string()));
        }
    }

    let mut header = Vec::new();
    for (k, v) in &f.req_headers {
        if !SKIP_HEADERS.contains(&k.to_lowercase().as_str()) {
            header.push((k.clone(), v.clone()));
        }
    }

    Params {
        query,
        body,
        header,
    }
}

pub fn analyze_params(f: &FlowRow) -> Value {
    let p = extract_params(f);
    let mut groups = serde_json::Map::new();
    let mut suspects: Vec<Value> = Vec::new();

    for (loc, pairs) in [
        ("query", &p.query),
        ("body", &p.body),
        ("header", &p.header),
    ] {
        let mut items = Vec::new();
        for (key, val) in pairs {
            let info = codec::classify(val);
            let score = codec::suspect_score(key, &info);
            let shown = if val.chars().count() <= 120 {
                val.clone()
            } else {
                format!("{}…", val.chars().take(120).collect::<String>())
            };
            let entry = json!({
                "location": loc, "key": key, "value": shown,
                "tags": info.tags, "note": info.note, "score": score,
            });
            if score >= 4 {
                suspects.push(entry.clone());
            }
            items.push(entry);
        }
        groups.insert(loc.into(), Value::Array(items));
    }

    suspects.sort_by(|a, b| b["score"].as_i64().cmp(&a["score"].as_i64()));
    json!({
        "flow": {"seq": f.seq, "method": f.method, "url": f.url},
        "params": groups,
        "signature_suspects": suspects,
        "hint": "score 高的字段更可能是签名/加密参数；用 compare_flows 对比两次请求确认哪些每次都变。",
    })
}

// ---------------------------------------------------------------------------
// 双请求 diff
// ---------------------------------------------------------------------------
fn to_map(pairs: &[(String, String)]) -> BTreeMap<String, String> {
    pairs.iter().cloned().collect()
}

fn diff_group(a: &BTreeMap<String, String>, b: &BTreeMap<String, String>) -> (Value, Vec<String>) {
    let mut added = serde_json::Map::new();
    let mut removed = serde_json::Map::new();
    let mut changed = serde_json::Map::new();
    let mut same = Vec::new();
    let mut changed_keys = Vec::new();

    for (k, v) in b {
        if !a.contains_key(k) {
            added.insert(k.clone(), Value::String(v.clone()));
        }
    }
    for (k, v) in a {
        match b.get(k) {
            None => {
                removed.insert(k.clone(), Value::String(v.clone()));
            }
            Some(bv) if bv != v => {
                changed.insert(k.clone(), json!({"a": v, "b": bv}));
                changed_keys.push(k.clone());
            }
            Some(_) => same.push(k.clone()),
        }
    }
    (
        json!({"changed": changed, "added": added, "removed": removed, "same_keys": same}),
        changed_keys,
    )
}

fn likely_role(key: &str, cls: &Classification) -> &'static str {
    let kl = key.to_lowercase();
    if cls
        .tags
        .iter()
        .any(|t| t == "timestamp_ms" || t == "timestamp_s")
    {
        return "timestamp";
    }
    if cls.tags.iter().any(|t| t.starts_with("hex:")) || kl.contains("sign") || kl.contains("sig") {
        return "signature";
    }
    if cls.tags.iter().any(|t| t == "uuid") || kl.contains("nonce") || kl.contains("rand") {
        return "nonce";
    }
    if cls.tags.iter().any(|t| t == "jwt") || kl.contains("token") {
        return "token";
    }
    "unknown"
}

pub fn compare_flows(a: &FlowRow, b: &FlowRow) -> Value {
    let pa = extract_params(a);
    let pb = extract_params(b);
    let mut diff = serde_json::Map::new();
    let mut volatile = Vec::new();
    let mut notes = serde_json::Map::new();

    let groups = [
        ("query", &pa.query, &pb.query),
        ("body", &pa.body, &pb.body),
        ("header", &pa.header, &pb.header),
    ];
    for (loc, ga, gb) in groups {
        let ma = to_map(ga);
        let mb = to_map(gb);
        let (d, changed_keys) = diff_group(&ma, &mb);
        for k in &changed_keys {
            volatile.push(format!("{loc}.{k}"));
            let bv = mb.get(k).cloned().unwrap_or_default();
            let cls = codec::classify(&bv);
            notes.insert(
                format!("{loc}.{k}"),
                json!({"tags": cls.tags, "likely": likely_role(k, &cls)}),
            );
        }
        diff.insert(loc.into(), d);
    }

    json!({
        "a": {"seq": a.seq, "url": a.url},
        "b": {"seq": b.seq, "url": b.url},
        "diff": diff,
        "volatile_fields": volatile,
        "volatile_notes": notes,
        "hint": "volatile_fields 是两次请求都变的字段：通常包含签名(sign)、时间戳(timestamp)、随机数(nonce)。用 track_param 看它跨更多请求是否每次都变。",
    })
}

// ---------------------------------------------------------------------------
// 跨请求参数追踪
// ---------------------------------------------------------------------------
fn is_monotonic(values: &[String]) -> bool {
    let mut nums = Vec::new();
    for v in values {
        match v.parse::<i64>() {
            Ok(n) => nums.push(n),
            Err(_) => return false,
        }
    }
    if nums.len() < 2 {
        return false;
    }
    let asc = nums.windows(2).all(|w| w[0] <= w[1]);
    let desc = nums.windows(2).all(|w| w[0] >= w[1]);
    asc || desc
}

pub fn track_param(rows: &[FlowRow], param: &str) -> Value {
    let mut occ: Vec<Value> = Vec::new();
    let mut values: Vec<String> = Vec::new();
    for f in rows {
        let p = extract_params(f);
        for (loc, pairs) in [
            ("query", &p.query),
            ("body", &p.body),
            ("header", &p.header),
        ] {
            for (k, v) in pairs {
                if k == param || k.rsplit('.').next() == Some(param) {
                    occ.push(json!({"seq": f.seq, "location": loc, "value": v}));
                    values.push(v.clone());
                }
            }
        }
    }

    let distinct: BTreeSet<&String> = values.iter().collect();
    let verdict = if occ.is_empty() {
        "not_found"
    } else if distinct.len() == 1 {
        "constant"
    } else if is_monotonic(&values) {
        "monotonic"
    } else if distinct.len() == values.len() {
        "always_changes"
    } else {
        "varies"
    };
    let hint = match verdict {
        "constant" => "恒定值 —— 多为 token/appKey/deviceId，可硬编码复用",
        "monotonic" => "单调递增 —— 多为时间戳或自增序号",
        "always_changes" => "每次都变 —— 强烈暗示签名(sign)或随机 nonce",
        "varies" => "部分变化 —— 需结合 analyze_params 进一步判断",
        _ => "未在抓到的请求中找到该参数",
    };

    let samples: Vec<Value> = occ.iter().take(20).cloned().collect();
    json!({
        "param": param,
        "count": occ.len(),
        "distinct_values": distinct.len(),
        "verdict": verdict,
        "hint": hint,
        "samples": samples,
    })
}

// ---------------------------------------------------------------------------
// API 聚类
// ---------------------------------------------------------------------------
fn normalize_path(path: &str) -> String {
    path.split('/')
        .map(|seg| {
            if RE_NUM_SEG.is_match(seg) {
                "{id}"
            } else if RE_HEX_SEG.is_match(seg) {
                "{hex}"
            } else {
                seg
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

pub fn api_patterns(rows: &[FlowRow], domain: Option<&str>) -> Value {
    struct Cluster {
        count: i64,
        query_keys: BTreeSet<String>,
        statuses: BTreeSet<i64>,
    }
    let mut clusters: BTreeMap<String, Cluster> = BTreeMap::new();

    for f in rows {
        let u = match Url::parse(&f.url) {
            Ok(u) => u,
            Err(_) => continue,
        };
        let host = u.host_str().unwrap_or("");
        if let Some(d) = domain {
            if !host.contains(d) {
                continue;
            }
        }
        let key = format!("{} {}{}", f.method, host, normalize_path(u.path()));
        let c = clusters.entry(key).or_insert(Cluster {
            count: 0,
            query_keys: BTreeSet::new(),
            statuses: BTreeSet::new(),
        });
        c.count += 1;
        for (k, _) in u.query_pairs() {
            c.query_keys.insert(k.into_owned());
        }
        if let Some(s) = f.status {
            c.statuses.insert(s);
        }
    }

    let mut endpoints: Vec<Value> = clusters
        .into_iter()
        .map(|(pattern, c)| {
            json!({
                "pattern": pattern,
                "count": c.count,
                "query_keys": c.query_keys.into_iter().collect::<Vec<_>>(),
                "statuses": c.statuses.into_iter().collect::<Vec<_>>(),
            })
        })
        .collect();
    endpoints.sort_by(|a, b| b["count"].as_i64().cmp(&a["count"].as_i64()));
    json!({"endpoints": endpoints.clone(), "total": endpoints.len()})
}

// ---------------------------------------------------------------------------
// 认证识别
// ---------------------------------------------------------------------------
pub fn detect_auth(rows: &[FlowRow]) -> Value {
    let mut bearer = false;
    let mut jwt = false;
    let mut basic = false;
    let mut api_key_headers: BTreeSet<String> = BTreeSet::new();
    let mut csrf: BTreeSet<String> = BTreeSet::new();
    let mut cookies: BTreeSet<String> = BTreeSet::new();

    static RE_JWT: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$").unwrap());

    for f in rows {
        let _hdrs: HashMap<String, String> = f.req_header_map();
        for (k, v) in &f.req_headers {
            let kl = k.to_lowercase();
            if kl == "authorization" {
                let vl = v.to_lowercase();
                if vl.starts_with("bearer ") {
                    bearer = true;
                    if RE_JWT.is_match(v.split_whitespace().last().unwrap_or("")) {
                        jwt = true;
                    }
                } else if vl.starts_with("basic ") {
                    basic = true;
                }
            } else if kl == "cookie" {
                for ck in v.split(';') {
                    if let Some(name) = ck.split('=').next() {
                        let name = name.trim();
                        if !name.is_empty() {
                            cookies.insert(name.to_string());
                        }
                    }
                }
            } else if kl.contains("csrf") || kl.contains("xsrf") {
                csrf.insert(k.clone());
            } else if [
                "api-key",
                "apikey",
                "x-token",
                "access-token",
                "app-key",
                "appkey",
            ]
            .iter()
            .any(|x| kl.contains(x))
            {
                api_key_headers.insert(k.clone());
            }
        }
    }

    json!({
        "bearer": bearer,
        "jwt": jwt,
        "basic": basic,
        "api_key_headers": api_key_headers.into_iter().collect::<Vec<_>>(),
        "csrf_headers": csrf.into_iter().collect::<Vec<_>>(),
        "cookie_names": cookies.into_iter().collect::<Vec<_>>(),
    })
}
