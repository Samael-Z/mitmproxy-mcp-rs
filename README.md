# mitmproxy-mcp-rs

命令行版 mitmproxy MCP server（**Rust 实现**），面向 **app 抓包与签名逆向分析**。

链路：**appproxy（手机 VPN 转发到上游代理） → 本工具（PC 端 MITM 抓包+解密+分析） → MCP（stdio 暴露给 AI 客户端）**。

这是 `mitmproxy-mcp-cli`（Python 版）的 Rust 重写：单二进制、无 Python 运行时依赖、启动快、内存低。

## 技术栈

| 能力 | 库 |
|---|---|
| MITM 抓包代理 | [hudsucker](https://crates.io/crates/hudsucker) 0.24（rustls + 自签 CA + HTTP/2/WS + 自动解压） |
| MCP（stdio） | [rmcp](https://crates.io/crates/rmcp) 1.7（官方 Rust SDK，`#[tool_router]`） |
| 存储 | rusqlite（bundled SQLite） |
| 重放 | reqwest（rustls） |
| TLS provider | aws-lc-rs（`prebuilt-nasm`，免装 nasm） |

## 构建

```bash
cd E:\DEV\mitmproxy-mcp-rs
cargo build --release
# 产物：target\release\mitmproxy-mcp-rs.exe
```

> Windows 需 MSVC C 工具链（VS Build Tools）与 cmake；`prebuilt-nasm` 已规避 nasm 依赖。

## 启动

```bash
mitmproxy-mcp-rs.exe [--db mitm_re_traffic.db] [--scope api.example.com,login.example.com]
```

stdio MCP server。代理默认**不自动启动**，由 AI 调 `start_proxy` 启动（**默认端口 18080**）。

### 接入 Claude Code / MCP 客户端

```json
{
  "mcpServers": {
    "mitmproxy-re": {
      "command": "E:\\DEV\\mitmproxy-mcp-rs\\target\\release\\mitmproxy-mcp-rs.exe",
      "args": ["--scope", "api.example.com"]
    }
  }
}
```

## CA 证书

首次 `start_proxy` 会在 `~/.mitmproxy-mcp-rs/` 生成自签 CA（`ca-cert.pem` + `ca-key.pem`），并持久化复用。HTTPS 抓包需客户端/手机信任 `ca-cert.pem`（路径见 `get_proxy_status`）。Android 7+ 需系统证书（配合 `MoveCertificate` / 重打包注入）。

## 典型逆向工作流

1. `start_proxy(host="0.0.0.0", port=18080)` —— 手机经 appproxy 把上游代理指向 `PC局域网IP:18080`。
2. 安装 CA → 触发 app 操作 → `list_flows` / `search_flows` 定位接口。
3. `analyze_params(flow)` —— 列出签名/加密嫌疑字段（md5/sha/hmac/base64/jwt/时间戳/nonce）。
4. 同接口操作两次 → `compare_flows(a, b)` —— 标出两次都变的字段（多为 sign/timestamp/nonce）。
5. `track_param("sign")` —— 确认是「每次都变」（签名）还是「恒定」（token）。
6. `decode_value(...)` —— 拆 base64/hex/jwt 编码层。
7. `replay_flow(flow, query_overrides_json='{"sign":"x"}')` —— 篡改签名重放，看服务端是否拒绝，反推签名覆盖范围。
8. `generate_code(flow)` / `export_curl(flow)` —— 导出脚手架。

## 工具一览（24 个）

| 分类 | 工具 |
|---|---|
| 生命周期 | `start_proxy` `stop_proxy` `get_proxy_status` `set_scope` |
| 抓包/查看 | `list_flows` `inspect_flow` `search_flows` `clear_flows` `import_flows` `export_flows` |
| 逆向分析 | `analyze_params` `compare_flows` `track_param` `decode_value` `detect_auth` `get_api_patterns` |
| 重放/验证 | `replay_flow` `set_session_variable` `extract_session_variable` `export_curl` `generate_code` |
| 拦截改写 | `add_intercept_rule` `list_rules` `clear_rules` |

`flow_id` 全部支持 **seq 序号** / **短 id 前缀** / **完整 id**。`import_flows`/`export_flows` 使用本工具的 JSON 格式（非 mitmproxy 私有 flow 格式）。

## 与 Python 版差异

- 请求/响应配对：hudsucker handler 按连接 FIFO 配对（HTTP/1.1 正确，HTTP/2 多路复用为近似）。
- 重放用 reqwest（非 curl_cffi），不复刻浏览器 TLS 指纹；如需指纹绕过用 Python 版或导出代码后自行处理。
- 导入/导出为 JSON（非 HAR/.flow）。
