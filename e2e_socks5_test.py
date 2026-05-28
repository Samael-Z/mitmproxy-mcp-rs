"""v0.2.0 SOCKS5 端到端冒烟：起代理（HTTP+SOCKS5 双口）→ 经 SOCKS5 抓 HTTPS → 验证落库 + compare。"""
import asyncio, json, os, sys, tempfile

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

PORT_HTTP = 18080
PORT_SOCKS5 = 11080  # 远离 Windows 保留段 (9816-9915, 10001-11074)
EXE = os.path.join(os.path.dirname(__file__), "target", "debug", "mitmproxy-mcp-rs.exe")
CA = os.path.expanduser("~/.mitmproxy-mcp-rs/ca-cert.pem")


def text(r): return r.content[0].text


async def main():
    db = os.path.join(tempfile.mkdtemp(), "e2e.db")
    params = StdioServerParameters(command=EXE, args=["--db", db])
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            print("TOOLS:", len((await session.list_tools()).tools))

            r = await session.call_tool("start_proxy", {
                "port": PORT_HTTP, "host": "127.0.0.1", "socks5_port": PORT_SOCKS5,
            })
            print("START:")
            for line in text(r).splitlines():
                print(" ", line)

            await asyncio.sleep(1.5)

            # 经 SOCKS5 入口发两次同接口、不同 sign 的 HTTPS 请求
            import requests  # requests[socks] 自带支持 socks5h://
            verify = CA if os.path.exists(CA) else False
            proxies = {
                "http":  f"socks5h://127.0.0.1:{PORT_SOCKS5}",
                "https": f"socks5h://127.0.0.1:{PORT_SOCKS5}",
            }
            for sign in ("098f6bcd4621d373cade4e832627b4f6", "ad0234829205b9033196ba818f7a872b"):
                try:
                    resp = requests.get(
                        f"https://httpbin.org/get?appkey=abc&ts=1716800000&sign={sign}",
                        proxies=proxies, verify=verify, timeout=15)
                    print(f"  socks5->https {resp.status_code}")
                except Exception as e:
                    print("  REQUEST ERROR:", repr(e)[:200])

            await asyncio.sleep(1.0)

            flows = json.loads(text(await session.call_tool("list_flows", {"limit": 10})))
            print("CAPTURED:", len(flows))
            for f in flows:
                print("   seq", f["seq"], f["method"], f["status"], f["url"][:70])

            if len(flows) >= 2:
                a, b = str(flows[1]["seq"]), str(flows[0]["seq"])
                cmp = json.loads(text(await session.call_tool(
                    "compare_flows", {"flow_id_a": a, "flow_id_b": b})))
                print("VOLATILE:", cmp["volatile_fields"])
                ap = json.loads(text(await session.call_tool("analyze_params", {"flow_id": b})))
                print("SUSPECTS:", [s["key"] for s in ap["signature_suspects"]])

            status = json.loads(text(await session.call_tool("get_proxy_status", {})))
            print("STATUS:", {k: status[k] for k in ("running", "port", "socks5_port", "captured")})

            print("STOP:", text(await session.call_tool("stop_proxy", {})))


asyncio.run(main())
