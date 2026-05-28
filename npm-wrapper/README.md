# mitmproxy-mcp-rs (npx wrapper)

[![npm](https://img.shields.io/npm/v/mitmproxy-mcp-rs.svg)](https://www.npmjs.com/package/mitmproxy-mcp-rs)

Thin npm shim around the [`mitmproxy-mcp-rs`](https://github.com/Samael-Z/mitmproxy-mcp-rs) Rust binary — a Model Context Protocol (MCP) server for app traffic capture and signature reverse engineering.

链路：appproxy（手机 VPN 转发）→ 本工具（PC 端 hudsucker MITM 抓包+解密+分析）→ MCP（stdio）。

## Use it with Claude Code / any MCP client

`.claude.json` / `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "mitmproxy-re": {
      "command": "npx",
      "args": ["-y", "mitmproxy-mcp-rs@latest"]
    }
  }
}
```

Pass CLI flags via `args`:

```json
{
  "mcpServers": {
    "mitmproxy-re": {
      "command": "npx",
      "args": ["-y", "mitmproxy-mcp-rs@latest", "--scope", "api.example.com"]
    }
  }
}
```

## How it works

On first invocation the shim downloads the platform-specific binary from the matching [GitHub Release](https://github.com/Samael-Z/mitmproxy-mcp-rs/releases) into a versioned cache directory, then `exec`s it. Subsequent runs skip the download. No npm dependencies, no postinstall.

Cache directory:
- Windows: `%LOCALAPPDATA%\mitmproxy-mcp-rs-npm\v<version>\`
- Linux/macOS: `~/.cache/mitmproxy-mcp-rs-npm/v<version>/`

## Supported platforms

| OS | Arch | Archive |
|---|---|---|
| Linux | x86_64 | `mitmproxy-mcp-rs-linux-x86_64.tar.gz` |
| macOS | arm64 | `mitmproxy-mcp-rs-macos-arm64.tar.gz` |
| Windows | x86_64 | `mitmproxy-mcp-rs-windows-x86_64.zip` |

Need another platform? File an issue.

## License

GPL-3.0-or-later. See [LICENSE](./LICENSE).
