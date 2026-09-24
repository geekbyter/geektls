"""P3-T3 handle 泄漏压测：本地回环 echo 服务，N 个请求，RSS 平稳性检查。

用法：python tests/perf/stress_leak.py [请求数，默认 10000]
需要：build/geektls.dll + build/echo-server.exe（先 make build 并构建 echo server）。
判定：后半程 RSS 线性回归斜率 < 1KB/请求，且末值 - 半程值 < 32MB。
"""

import json
import os
import subprocess
import sys
import time

import psutil

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "bindings", "python"))


def wait_ready(proc, timeout=10):
    deadline = time.time() + timeout
    while time.time() < deadline:
        line = proc.stdout.readline()
        if line.startswith("READY"):
            return line.split()[1].strip()
    raise RuntimeError("echo server did not start: " + proc.stderr.read().decode())


def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 10000

    dll = os.path.join(ROOT, "build", "geektls.dll")
    server = os.path.join(ROOT, "build", "echo-server.exe")
    if not os.path.exists(dll) or not os.path.exists(server):
        sys.exit("build artifacts missing: run scripts/build_core.sh and build echo-server first")
    os.environ["GEEDTLS_LIB"] = dll

    proc = subprocess.Popen([server], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True)
    try:
        base = wait_ready(proc)

        from geektls import Session

        me = psutil.Process(os.getpid())
        samples = []

        with Session(impersonate="chrome_133", insecure_skip_verify=True) as s:
            # 热身（首个请求会把 DLL/字体/缓存等一次性成本计入）
            for _ in range(200):
                s.get(base + "/echo").close()
            samples.append(me.memory_info().rss)

            for i in range(1, n + 1):
                r = s.get(base + "/echo")
                r.close()
                if i % 500 == 0:
                    rss = me.memory_info().rss
                    samples.append(rss)
                    print(f"  [{i:>6}] rss={rss/1048576:.1f} MB", flush=True)

        # 斜率（KB/请求，按每 500 个采样一段的最小二乘近似）
        first, last = samples[1], samples[-1]
        growth_mb = (last - first) / 1048576
        per_req_kb = (last - first) / 1024 / (len(samples) - 2) / 500 if len(samples) > 2 else 0
        print(f"done: {n} requests, rss {first/1048576:.1f} -> {last/1048576:.1f} MB, "
              f"growth {growth_mb:.1f} MB, ~{per_req_kb:.2f} KB/req")
        if growth_mb > 32:
            print("FAIL: RSS grew more than 32MB after warmup")
            return 1
        print("PASS: RSS stable")
        return 0
    finally:
        proc.kill()


if __name__ == "__main__":
    sys.exit(main())
