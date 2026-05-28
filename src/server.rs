//! rmcp ServerHandler：注册全部逆向抓包工具（stdio）。

use std::collections::HashMap;
use std::sync::Arc;

use rmcp::{
    handler::server::router::tool::ToolRouter, handler::server::wrapper::Parameters, model::*,
    tool, tool_handler, tool_router, ErrorData as McpError, ServerHandler,
};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::model::Rule;
use crate::proxy::ProxyController;
use crate::{analysis, bodies, codec, codegen, replay};

fn ok_json(v: &Value) -> Result<CallToolResult, McpError> {
    let s = serde_json::to_string_pretty(v).unwrap_or_else(|_| v.to_string());
    Ok(CallToolResult::success(vec![Content::text(s)]))
}

fn ok_text(s: impl Into<String>) -> Result<CallToolResult, McpError> {
    Ok(CallToolResult::success(vec![Content::text(s.into())]))
}

// ----- 参数结构体 -----
#[derive(Debug, Deserialize, JsonSchema)]
pub struct StartProxyParams {
    /// 监听端口（默认 18080）
    pub port: Option<u16>,
    /// 监听地址（默认 127.0.0.1；给手机用填 0.0.0.0）
    pub host: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SetScopeParams {
    /// 抓包白名单域名（空数组=抓全部）
    pub allowed_domains: Vec<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListFlowsParams {
    pub limit: Option<i64>,
    pub domain: Option<String>,
    pub method: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct InspectFlowParams {
    /// seq 序号 / 短 id / 完整 id
    pub flow_id: String,
    pub full_body: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SearchFlowsParams {
    pub query: Option<String>,
    pub domain: Option<String>,
    pub method: Option<String>,
    pub status: Option<i64>,
    pub limit: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PathParams {
    pub path: String,
    pub append: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct FlowIdParams {
    pub flow_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct CompareParams {
    pub flow_id_a: String,
    pub flow_id_b: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct TrackParamParams {
    pub param_name: String,
    pub limit: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DecodeParams {
    pub value: String,
    /// 解码步骤链（如 ["base64","gzip"]），省略则自动识别
    pub chain: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct LimitParams {
    pub limit: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ApiPatternsParams {
    pub domain: Option<String>,
    pub limit: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ReplayParams {
    pub flow_id: String,
    pub method: Option<String>,
    /// JSON 对象字符串，覆盖/新增请求头
    pub headers_json: Option<String>,
    pub body: Option<String>,
    /// JSON 对象字符串，覆盖 query 参数
    pub query_overrides_json: Option<String>,
    pub timeout: Option<f64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SetVarParams {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ExtractVarParams {
    pub name: String,
    pub flow_id: String,
    pub regex: String,
    pub group: Option<usize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GenCodeParams {
    pub flow_id: String,
    /// requests | curl_cffi
    pub framework: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct AddRuleParams {
    pub rule_id: String,
    /// block | replace_body | inject_header
    pub action: String,
    /// request | response（默认 request）
    pub phase: Option<String>,
    /// URL 子串匹配（省略=全部）
    pub url_match: Option<String>,
    pub header: Option<String>,
    pub value: Option<String>,
    pub pattern: Option<String>,
    pub replacement: Option<String>,
}

#[derive(Clone)]
pub struct Server {
    ctl: Arc<ProxyController>,
    #[allow(dead_code)]
    tool_router: ToolRouter<Server>,
}

#[tool_router]
impl Server {
    pub fn new(ctl: Arc<ProxyController>) -> Self {
        Self {
            ctl,
            tool_router: Self::tool_router(),
        }
    }

    fn need_flow(&self, flow_id: &str) -> Result<crate::model::FlowRow, Value> {
        self.ctl.store.get(flow_id).ok_or_else(
            || json!({"error": format!("未找到 flow: {flow_id}（可用 seq 序号/短id/完整id）")}),
        )
    }

    // ----- 生命周期/配置 -----
    #[tool(
        description = "启动 mitmproxy 抓包代理。手机经 appproxy 转发时把 host 设为 0.0.0.0。默认端口 18080（避开 Windows 保留端口段）。"
    )]
    async fn start_proxy(
        &self,
        Parameters(p): Parameters<StartProxyParams>,
    ) -> Result<CallToolResult, McpError> {
        let port = p.port.unwrap_or(18080);
        let host = p.host.unwrap_or_else(|| "127.0.0.1".into());
        match self.ctl.start(port, &host) {
            Ok(msg) => ok_text(msg),
            Err(e) => ok_json(&json!({"error": e.to_string()})),
        }
    }

    #[tool(description = "停止抓包代理并释放端口。")]
    async fn stop_proxy(&self) -> Result<CallToolResult, McpError> {
        ok_text(self.ctl.stop())
    }

    #[tool(description = "查看代理运行状态、抓包数量、scope、规则、CA 证书路径。")]
    async fn get_proxy_status(&self) -> Result<CallToolResult, McpError> {
        ok_json(&self.ctl.status())
    }

    #[tool(description = "设置抓包白名单域名（仅记录这些域名，降噪）。传空数组=抓全部。")]
    async fn set_scope(
        &self,
        Parameters(p): Parameters<SetScopeParams>,
    ) -> Result<CallToolResult, McpError> {
        *self.ctl.scope.lock().unwrap() = p.allowed_domains.clone();
        ok_json(&json!({"scope": p.allowed_domains}))
    }

    // ----- 抓包/查看 -----
    #[tool(description = "列出最近抓到的请求摘要（seq 序号可直接用于其他工具）。")]
    async fn list_flows(
        &self,
        Parameters(p): Parameters<ListFlowsParams>,
    ) -> Result<CallToolResult, McpError> {
        let v = self.ctl.store.summary(
            p.limit.unwrap_or(30),
            p.domain.as_deref(),
            p.method.as_deref(),
        );
        ok_json(&json!(v))
    }

    #[tool(
        description = "查看一条 flow 的完整请求+响应（JSON 美化），附 curl。flow_id 支持 seq/短id/完整id。"
    )]
    async fn inspect_flow(
        &self,
        Parameters(p): Parameters<InspectFlowParams>,
    ) -> Result<CallToolResult, McpError> {
        let f = match self.need_flow(&p.flow_id) {
            Ok(f) => f,
            Err(e) => return ok_json(&e),
        };
        let limit = if p.full_body.unwrap_or(false) {
            None
        } else {
            Some(2000usize)
        };
        let resp = if f.status.is_some() {
            json!({
                "status": f.status,
                "headers": f.resp_headers,
                "body": bodies::pretty_body(f.resp_body.as_deref(), limit),
            })
        } else {
            Value::Null
        };
        ok_json(&json!({
            "id": f.id,
            "seq": f.seq,
            "request": {
                "method": f.method,
                "url": f.url,
                "headers": f.req_headers,
                "body": bodies::pretty_body(f.req_body.as_deref(), limit),
            },
            "response": resp,
            "curl": codegen::to_curl(&f),
        }))
    }

    #[tool(description = "按关键字(url/请求体/响应体/请求头)、域名、方法、状态码检索抓到的请求。")]
    async fn search_flows(
        &self,
        Parameters(p): Parameters<SearchFlowsParams>,
    ) -> Result<CallToolResult, McpError> {
        let v = self.ctl.store.search(
            p.query.as_deref(),
            p.domain.as_deref(),
            p.method.as_deref(),
            p.status,
            p.limit.unwrap_or(50),
        );
        ok_json(&json!(v))
    }

    #[tool(description = "清空已抓取的流量库。")]
    async fn clear_flows(&self) -> Result<CallToolResult, McpError> {
        let n = self.ctl.store.clear();
        ok_json(&json!({"cleared": n}))
    }

    #[tool(description = "从 JSON 文件导入流量（append=false 先清空）。")]
    async fn import_flows(
        &self,
        Parameters(p): Parameters<PathParams>,
    ) -> Result<CallToolResult, McpError> {
        match self
            .ctl
            .store
            .import_json(&p.path, p.append.unwrap_or(false))
        {
            Ok(n) => ok_json(&json!({"imported": n})),
            Err(e) => ok_json(&json!({"error": e.to_string()})),
        }
    }

    #[tool(description = "把当前流量库导出为 JSON 文件。")]
    async fn export_flows(
        &self,
        Parameters(p): Parameters<PathParams>,
    ) -> Result<CallToolResult, McpError> {
        match self.ctl.store.export_json(&p.path) {
            Ok(n) => ok_json(&json!({"exported": n, "path": p.path})),
            Err(e) => ok_json(&json!({"error": e.to_string()})),
        }
    }

    // ----- 逆向分析 -----
    #[tool(
        description = "拆解一条 flow 的 query/body/header 参数，识别每个值的特征(md5/sha/hmac/base64/jwt/时间戳/nonce)，排出签名/加密嫌疑字段。"
    )]
    async fn analyze_params(
        &self,
        Parameters(p): Parameters<FlowIdParams>,
    ) -> Result<CallToolResult, McpError> {
        match self.need_flow(&p.flow_id) {
            Ok(f) => ok_json(&analysis::analyze_params(&f)),
            Err(e) => ok_json(&e),
        }
    }

    #[tool(
        description = "对比两条 flow 的参数差异，标出两次都变的字段(签名/时间戳/nonce 强信号)——签名逆向最关键工具。"
    )]
    async fn compare_flows(
        &self,
        Parameters(p): Parameters<CompareParams>,
    ) -> Result<CallToolResult, McpError> {
        let a = match self.need_flow(&p.flow_id_a) {
            Ok(f) => f,
            Err(e) => return ok_json(&e),
        };
        let b = match self.need_flow(&p.flow_id_b) {
            Ok(f) => f,
            Err(e) => return ok_json(&e),
        };
        ok_json(&analysis::compare_flows(&a, &b))
    }

    #[tool(
        description = "在抓到的所有请求中追踪同名参数的取值，判定它是 恒定(token)/单调递增(时间戳)/每次都变(签名)。"
    )]
    async fn track_param(
        &self,
        Parameters(p): Parameters<TrackParamParams>,
    ) -> Result<CallToolResult, McpError> {
        let rows = self.ctl.store.all(Some(p.limit.unwrap_or(100)));
        ok_json(&analysis::track_param(&rows, &p.param_name))
    }

    #[tool(
        description = "解码一个字符串。chain 指定步骤(如 [\"base64\",\"gzip\"])依次解；省略则自动识别 base64/base64url/hex/url/jwt。"
    )]
    async fn decode_value(
        &self,
        Parameters(p): Parameters<DecodeParams>,
    ) -> Result<CallToolResult, McpError> {
        ok_json(&codec::decode_value(&p.value, p.chain))
    }

    #[tool(description = "分析抓到的请求，识别认证方式(Bearer/JWT/Basic/API-Key 头/Cookie/CSRF)。")]
    async fn detect_auth(
        &self,
        Parameters(p): Parameters<LimitParams>,
    ) -> Result<CallToolResult, McpError> {
        let rows = self.ctl.store.all(Some(p.limit.unwrap_or(200)));
        ok_json(&analysis::detect_auth(&rows))
    }

    #[tool(
        description = "把抓到的请求按归一化路径聚类，输出 API 结构图(路径模板/次数/query 字段/状态码)。"
    )]
    async fn get_api_patterns(
        &self,
        Parameters(p): Parameters<ApiPatternsParams>,
    ) -> Result<CallToolResult, McpError> {
        let rows = self.ctl.store.all(Some(p.limit.unwrap_or(500)));
        ok_json(&analysis::api_patterns(&rows, p.domain.as_deref()))
    }

    // ----- 重放/验证/代码生成 -----
    #[tool(
        description = "用 reqwest 重放一条请求，可覆盖 method/headers/body/query。改单参数重放看服务端是否拒绝，可反推该参数是否被签名覆盖。值里可用 ${var} 引用 session 变量。"
    )]
    async fn replay_flow(
        &self,
        Parameters(p): Parameters<ReplayParams>,
    ) -> Result<CallToolResult, McpError> {
        let headers: Option<HashMap<String, String>> = p
            .headers_json
            .as_deref()
            .and_then(|s| serde_json::from_str(s).ok());
        let query_overrides: Option<HashMap<String, String>> = p
            .query_overrides_json
            .as_deref()
            .and_then(|s| serde_json::from_str(s).ok());
        let v = replay::replay(
            &self.ctl.store,
            &self.ctl.session,
            &p.flow_id,
            p.method,
            headers,
            p.body,
            query_overrides,
            p.timeout.unwrap_or(30.0),
        )
        .await;
        ok_json(&v)
    }

    #[tool(description = "手动设置一个 session 变量，供 replay_flow 用 ${name} 引用。")]
    async fn set_session_variable(
        &self,
        Parameters(p): Parameters<SetVarParams>,
    ) -> Result<CallToolResult, McpError> {
        self.ctl
            .session
            .lock()
            .unwrap()
            .insert(p.name.clone(), p.value);
        ok_json(&json!({"set": p.name}))
    }

    #[tool(
        description = "用正则从某条 flow 的响应体提取值，存为 session 变量(如提取登录 token 供后续重放)。"
    )]
    async fn extract_session_variable(
        &self,
        Parameters(p): Parameters<ExtractVarParams>,
    ) -> Result<CallToolResult, McpError> {
        let f = match self.need_flow(&p.flow_id) {
            Ok(f) => f,
            Err(e) => return ok_json(&e),
        };
        let body = f.resp_body.unwrap_or_default();
        let re = match regex::Regex::new(&p.regex) {
            Ok(r) => r,
            Err(e) => return ok_json(&json!({"error": format!("正则无效: {e}")})),
        };
        match re.captures(&body) {
            Some(caps) => {
                let g = p.group.unwrap_or(1);
                let val = caps
                    .get(g)
                    .or_else(|| caps.get(0))
                    .map(|m| m.as_str().to_string())
                    .unwrap_or_default();
                self.ctl
                    .session
                    .lock()
                    .unwrap()
                    .insert(p.name.clone(), val.clone());
                ok_json(&json!({"set": p.name, "value": val}))
            }
            None => ok_json(&json!({"error": format!("正则未匹配: {}", p.regex)})),
        }
    }

    #[tool(description = "把一条 flow 导出为 curl 命令。")]
    async fn export_curl(
        &self,
        Parameters(p): Parameters<FlowIdParams>,
    ) -> Result<CallToolResult, McpError> {
        match self.need_flow(&p.flow_id) {
            Ok(f) => ok_text(codegen::to_curl(&f)),
            Err(e) => ok_json(&e),
        }
    }

    #[tool(description = "从一条 flow 生成 Python 客户端代码。framework: requests | curl_cffi。")]
    async fn generate_code(
        &self,
        Parameters(p): Parameters<GenCodeParams>,
    ) -> Result<CallToolResult, McpError> {
        match self.need_flow(&p.flow_id) {
            Ok(f) => ok_text(codegen::to_python(
                &f,
                &p.framework.unwrap_or_else(|| "requests".into()),
            )),
            Err(e) => ok_json(&e),
        }
    }

    // ----- 拦截/改写 -----
    #[tool(
        description = "添加拦截/改写规则。action: block|replace_body|inject_header；phase: request|response；url_match 为 URL 子串(省略=全部)。"
    )]
    async fn add_intercept_rule(
        &self,
        Parameters(p): Parameters<AddRuleParams>,
    ) -> Result<CallToolResult, McpError> {
        if !["block", "replace_body", "inject_header"].contains(&p.action.as_str()) {
            return ok_json(&json!({"error": "action 必须是 block/replace_body/inject_header"}));
        }
        let rule = Rule {
            rule_id: p.rule_id.clone(),
            action: p.action,
            phase: p.phase.unwrap_or_else(|| "request".into()),
            url_match: p.url_match,
            header: p.header,
            value: p.value,
            pattern: p.pattern,
            replacement: p.replacement,
        };
        let mut rules = self.ctl.rules.lock().unwrap();
        rules.retain(|r| r.rule_id != p.rule_id);
        rules.push(rule);
        ok_json(&json!({"added": p.rule_id, "rules": rules.len()}))
    }

    #[tool(description = "列出当前生效的拦截/改写规则。")]
    async fn list_rules(&self) -> Result<CallToolResult, McpError> {
        let rules = self.ctl.rules.lock().unwrap().clone();
        ok_json(&json!(rules))
    }

    #[tool(description = "清空所有拦截/改写规则。")]
    async fn clear_rules(&self) -> Result<CallToolResult, McpError> {
        let mut rules = self.ctl.rules.lock().unwrap();
        let n = rules.len();
        rules.clear();
        ok_json(&json!({"cleared": n}))
    }
}

#[tool_handler]
impl ServerHandler for Server {
    fn get_info(&self) -> ServerInfo {
        let mut info = ServerInfo::default();
        info.capabilities = ServerCapabilities::builder().enable_tools().build();
        info.instructions = Some(
            "mitmproxy 抓包 + 签名逆向分析。先 start_proxy 启动代理(默认 9876)，客户端/手机走代理并装 CA；再用 list_flows/analyze_params/compare_flows/track_param/replay_flow 做逆向。".into(),
        );
        info
    }
}
