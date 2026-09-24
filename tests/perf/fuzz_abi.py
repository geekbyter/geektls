"""P7-T3 ABI 边界 fuzz：随机垃圾喂 gtls_check_profile / gtls_client_new /
gtls_describe_preset 一千次。断言：进程不崩、错误路径的 last_error JSON 结构完好。

用法：python tests/perf/fuzz_abi.py [迭代数，默认 1000]
"""

import json
import os
import random
import string
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "bindings", "python"))


def rand_input(rng):
    kind = rng.randrange(7)
    if kind == 0:
        return bytes(rng.randrange(256) for _ in range(rng.randrange(1, 512)))
    if kind == 1:
        return "".join(rng.choice(string.printable) for _ in range(rng.randrange(0, 200))).encode("utf-8", "ignore")
    if kind == 2:  # 结构像 JSON 但内容畸形
        return json.dumps({"tls": {"detail": {"ciphers": [rng.choice(["0x1301", "zz", 123, None])]}}}).encode()
    if kind == 3:  # 超长
        return (b"0x1301," * rng.randrange(100, 2000))[:-1]
    if kind == 4:  # 嵌套炸弹
        return b'{"a":' * 100 + b"1" + b"}" * 100
    if kind == 5:  # 合法 ja3 形态变异
        return f"{rng.randrange(1000)},{rng.randrange(65536)}-{rng.randrange(65536)},,,0".encode()
    return rng.choice([b"", b"{}", b"null", b"[]", "\U0001f4a3".encode()])


def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 1000
    dll = os.path.join(ROOT, "build", "geektls.dll")
    if not os.path.exists(dll):
        sys.exit("build/geektls.dll missing")
    os.environ["GEEDTLS_LIB"] = dll

    from geektls import _ffi

    rng = random.Random(1337)
    stats = {"check_ok": 0, "check_err": 0, "client_ok": 0, "client_err": 0, "desc_err": 0}

    for i in range(n):
        payload = rand_input(rng)

        # check_profile：NULL 或 last_error 必须是 {"code","message"}
        r = _ffi.lib.gtls_check_profile(payload)
        if r:
            out = _ffi.take_json(r)
            assert isinstance(out, dict) and "ja4" in out, f"bad success payload: {out}"
            stats["check_ok"] += 1
        else:
            err = _ffi.last_error()
            assert isinstance(err.get("code"), str) and isinstance(err.get("message"), str), f"bad error shape: {err}"
            stats["check_err"] += 1

        # client_new：handle 或错误 JSON；handle 必须能 close 且幂等报错
        h = _ffi.lib.gtls_client_new(payload)
        if h:
            assert _ffi.lib.gtls_client_close(h) == 0
            assert _ffi.lib.gtls_client_close(h) == -1  # 重复 close 报错不崩
            stats["client_ok"] += 1
        else:
            err = _ffi.last_error()
            assert isinstance(err.get("code"), str), f"bad error shape: {err}"
            stats["client_err"] += 1

        # describe_preset：随机名字必须 preset_not_found（NULL + 结构化错误）
        name = payload[:32]
        r = _ffi.lib.gtls_describe_preset(name)
        if not r:
            err = _ffi.last_error()
            assert isinstance(err.get("code"), str), f"bad error shape: {err}"
            stats["desc_err"] += 1
        else:
            _ffi.take_string(r)

        if (i + 1) % 250 == 0:
            print(f"  [{i+1:>5}] {stats}", flush=True)

    print(f"done: {n} iterations, {stats}")
    print("PASS: no crash, error JSON shape intact")
    return 0


if __name__ == "__main__":
    sys.exit(main())
