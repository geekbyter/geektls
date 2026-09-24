"""P7-T4 性能基准（Python FFI 链路 + FFI 开销 + 冷启动）。

用法：GEEDTLS_BENCH=1 python tests/perf/bench_python.py
依赖：build/geektls.dll + build/echo-server.exe
"""

import json
import os
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "bindings", "python"))


def start_echo():
    proc = subprocess.Popen([os.path.join(ROOT, "build", "echo-server.exe")],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    for line in proc.stdout:
        if line.startswith("READY"):
            return proc, line.split()[1].strip()
    raise RuntimeError("echo server failed")


def _profile_without_ech():
    # 同 bench_node.js 注释：剥 ECH 测稳态（本机 echo 的 H3 服务端拒 ECH）
    from geektls import _ffi
    p = _ffi.take_json(_ffi.lib.gtls_describe_preset(b"chrome_133"))
    p["tls"]["detail"]["extensions"] = [
        e for e in p["tls"]["detail"]["extensions"] if e["type"] != 65037]
    return p


def throughput(base, concurrency, dur=10.0):
    from geektls import Session
    profile = _profile_without_ech()
    stop = threading.Event()
    counts = [0] * concurrency
    errs = [0]

    def worker(idx):
        with Session(profile=profile, insecure_skip_verify=True) as s:
            n = 0
            while not stop.is_set():
                try:
                    r = s.get(base + "/echo")
                    r.close()
                    n += 1
                except Exception:
                    errs[0] += 1
            counts[idx] = n

    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futs = [pool.submit(worker, i) for i in range(concurrency)]
        time.sleep(dur)
        stop.set()
        for f in futs:
            f.result()
    total = sum(counts)
    return total, total / dur, errs[0]


def ffi_overhead(n=100000):
    from geektls import _ffi
    # gtls_version：最轻量 FFI 调用
    t0 = time.perf_counter()
    for _ in range(n):
        _ffi.take_string(_ffi.lib.gtls_version())
    v_sec = (time.perf_counter() - t0) / n * 1e6

    # gtls_check_profile：含 JSON 解析+编译+自算的典型调用
    payload = b'{"ja3":"771,4865-4866-4867,0-10-11,29-23,0"}'
    t0 = time.perf_counter()
    for _ in range(n):
        r = _ffi.lib.gtls_check_profile(payload)
        if r:
            _ffi.take_string(r)
    c_sec = (time.perf_counter() - t0) / n * 1e6
    return v_sec, c_sec


def cold_start(base, profile):
    from geektls import Session
    t0 = time.perf_counter()
    import geektls  # DLL 已加载；测的是 Session 初始化 + 首次请求
    t1 = time.perf_counter()
    with Session(profile=profile, insecure_skip_verify=True) as s:
        t2 = time.perf_counter()
        s.get(base + "/echo").close()
        t3 = time.perf_counter()
    return (t1 - t0) * 1e3, (t2 - t1) * 1e3, (t3 - t2) * 1e3


def main():
    dll = os.path.join(ROOT, "build", "geektls.dll")
    os.environ["GEEDTLS_LIB"] = dll
    proc, base = start_echo()
    try:
        print(f"echo server: {base}")
        for c in (10, 50, 100):
            total, rps, errs = throughput(base, c)
            print(f"python-ffi concurrency={c:3d}: {total} reqs in 10s = {rps:.0f} req/s (errors: {errs})")

        v, c = ffi_overhead()
        print(f"ffi overhead: gtls_version {v:.2f} µs/call, gtls_check_profile {c:.2f} µs/call (100k iterations)")

        a, b, csec = cold_start(base, _profile_without_ech())
        print(f"cold start: dll-ready {a:.1f} ms, session-init {b:.1f} ms, first-request {csec:.1f} ms")
    finally:
        proc.kill()


if __name__ == "__main__":
    main()
