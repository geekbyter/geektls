"""P6-T3 验收：netstack 档（gVisor 用户态栈）打 nginx 采集端，
断言 ja4tcp 五分量与 profile 设定值逐项相等。

运行（WSL root——AF_PACKET + iptables 需要）：
    wsl -u root -- python3 /mnt/d/work/tls/geektls/tests/e2e/nginx-l2/verify_p6t3.py

SYN window 的 gVisor 公式（connect.go initialReceiveWindow）：
    window = min(rcvbuf, 65535, InitialCwnd(10)*MSS*2) 再按 wscale 向下对齐。
本用例取值：mss=1460（routeWnd=29200）、window=29184（=114×256，ws=8 对齐
不变、≤29200）、wscale=8（TCPReceiveBufferSizeRangeOption.Max=65535<<8）。
"""

import json
import os
import sys

ROOT = "/mnt/d/work/tls/geektls"
os.environ.setdefault("GEEDTLS_LIB", os.path.join(ROOT, "build", "libgeektls.so"))
sys.path.insert(0, os.path.join(ROOT, "bindings", "python"))

TARGET = os.environ.get("GEEKTLS_NGINX_L2_URL", "https://10.99.0.1:8444/ngf-debug")

# 设定值（公式见 docstring）
WANT = {
    "ja4tcp_window": "29184",
    "ja4tcp_options": "2-4-8-1-3",          # MSS,SACK,TS,NOP,WS（gVisor Linux 族固定序）
    "ja4tcp_options_text": "MSS,SACK,TS,NOP,WS",
    "ja4tcp_mss": "1460",
    "ja4tcp_window_scale": "8",
}

TCP = {
    "mode": "netstack",
    "ttl": 42,
    "df": True,
    "mss": 1460,
    "window_size": 29184,
    "window_scale": 8,
}


def main():
    import geektls

    p = geektls.describe_preset("chrome_133")
    p["tcp"] = TCP

    with geektls.Session(profile=p, insecure_skip_verify=True) as s:
        r = s.get(TARGET)
        assert r.status_code == 200, r.status_code
        got = r.json()

    rows = []
    ok = True
    for k, want in WANT.items():
        g = str(got.get(k, ""))
        match = g == want
        ok &= match
        rows.append((k, want, g, "MATCH" if match else "DIFF"))
    rows.append(("ja4tcp（合成串）", "", str(got.get("ja4tcp", "")), "info"))

    print("=" * 64)
    print("P6-T3 netstack 档 ja4tcp 五分量对照（设定 vs nginx 采集）")
    print("=" * 64)
    for k, w, g, st in rows:
        print(f"  {k:26s} 设定={w:12s} 采集={g:12s} {st}")
    if not ok:
        sys.exit("P6-T3 FAILED")
    print("P6-T3 PASS：netstack 档五分量逐项相等")


if __name__ == "__main__":
    main()
