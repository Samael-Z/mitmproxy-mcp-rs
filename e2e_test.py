"""端到端冒烟测试：用 MCP stdio 客户端驱动 Rust 二进制，跑通 抓包->分析 全链路。

用法: python e2e_test.py [PORT]   # PORT 默认 18080（避开 Windows 保留端口段）
需要: pip install mcp requests ；并能访问 httpbin.org。
"""
import asyncio, json, os, sys, tempfile

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 18080
EXE = os.path.join(os.path.dirname(__file__), "target", "debug", "mitmproxy-mcp-rs.exe")
CA = os.path.expanduser("~/.mitmproxy-mcp-rs/ca-cert.pem")


def text(result):
    return result.content[0].text


async def main():
    db = os.path.join(tempfile.mkdtemp(), "e2e.db")
    params = StdioServerParameters(command=EXE, args=["--db", db])
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            print("TOOLS:", len((await session.list_tools()).tools))

            r = await session.call_tool("start_proxy", {"port": PORT, "host": "127.0.0.1"})
            print("START:", text(r).splitlines()[0])
            await asyncio.sleep(1.5)

            import requests
            verify = CA if os.path.exists(CA) else False
            proxies = {"http": f"http://127.0.0.1:{PORT}", "https": f"http://127.0.0.1:{PORT}"}
            for sign in ("098f6bcd4621d373cade4e832627b4f6", "ad0234829205b9033196ba818f7a872b"):
                try:
                    resp = requests.get(
                        f"https://httpbin.org/get?appkey=abc&ts=1716800000&sign={sign}",
                        proxies=proxies, verify=verify, timeout=15)
                    print("  via-proxy", resp.status_code)
                except Exception as e:
                    print("  REQUEST ERROR:", repr(e)[:160])
            await asyncio.sleep(1.0)

            flows = json.loads(text(await session.call_tool("list_flows", {"limit": 10})))
            print("CAPTURED:", len(flows))
            for f in flows:
                print("   seq", f["seq"], f["method"], f["status"], f["url"][:60])

            if len(flows) >= 2:
                a, b = str(flows[1]["seq"]), str(flows[0]["seq"])
                cmp = json.loads(text(await session.call_tool(
                    "compare_flows", {"flow_id_a": a, "flow_id_b": b})))
                print("VOLATILE:", cmp["volatile_fields"])
                ap = json.loads(text(await session.call_tool("analyze_params", {"flow_id": b})))
                print("SUSPECTS:", [s["key"] for s in ap["signature_suspects"]])

            dv = json.loads(text(await session.call_tool(
                "decode_value", {"value": "aGVsbG8gd29ybGQ="})))
            print("DECODE:", dv["decodings"][0]["result"] if dv["decodings"] else None)
            print("STOP:", text(await session.call_tool("stop_proxy", {})))


asyncio.run(main())
