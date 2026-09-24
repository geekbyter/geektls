"""P3-T4 e2e harness（pytest 形态）：预设 × 请求 → selfcheck + 响应断言。

fixture 起本地 Go echo server（h2 + http/1.1 双协议，自签证书）。
运行：python -m pytest tests/e2e/python -v
前置：build/geektls.dll + build/echo-server.exe。
"""

import json
import os
import subprocess
import time

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
sys_path_added = os.path.join(ROOT, "bindings", "python")


def _ensure_lib():
    os.environ.setdefault("GEEDTLS_LIB", os.path.join(ROOT, "build", "geektls.dll"))
    if os.path.join(ROOT, "bindings", "python") not in os.sys.path:
        os.sys.path.insert(0, os.path.join(ROOT, "bindings", "python"))


@pytest.fixture(scope="session")
def echo_server():
    exe = os.path.join(ROOT, "build", "echo-server.exe")
    if not os.path.exists(exe):
        pytest.skip("echo-server.exe not built (go build ./cmd/echo-server in tests/e2e)")
    proc = subprocess.Popen([exe], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True)
    try:
        deadline = time.time() + 10
        base = None
        while time.time() < deadline:
            line = proc.stdout.readline()
            if line.startswith("READY"):
                base = line.split()[1].strip()
                break
        if base is None:
            pytest.fail("echo server did not start")
        yield base
    finally:
        proc.kill()


@pytest.fixture(scope="session")
def presets():
    _ensure_lib()
    from geektls import _ffi
    names = _ffi.take_json(_ffi.lib.gtls_list_presets())
    assert isinstance(names, list) and len(names) >= 7
    return names


def test_version_abi(presets):
    _ensure_lib()
    import geektls
    v = geektls.version()
    assert v["abi"] == 1
    assert v["core"] == "0.1.0"


def test_preset_matrix_echo(echo_server, presets):
    """全预设：GET /echo 200 + selfcheck 结构合法 + JA4 格式正确。"""
    _ensure_lib()
    from geektls import Session
    for name in presets:
        with Session(impersonate=name, insecure_skip_verify=True) as s:
            r = s.get(echo_server + "/echo")
            assert r.status == 200, name
            assert r.used_protocol == "h2", name
            sc = r.selfcheck
            assert len(sc["ja3_hash"]) == 32, name
            parts = sc["ja4"].split("_")
            assert len(parts) == 3 and parts[0].startswith("t13d"), (name, sc["ja4"])
            body = json.loads(r.read())
            assert body["proto"] == "HTTP/2.0", name
            r.close()


def test_redirect_and_cookie(echo_server):
    _ensure_lib()
    from geektls import Session
    with Session(impersonate="firefox_120", insecure_skip_verify=True) as s:
        r = s.get(echo_server + "/redirect")
        assert r.status == 200
        r.close()
        s.get(echo_server + "/set-cookie").close()
        r = s.get(echo_server + "/check-cookie")
        assert r.read() == b"abc123"
        r.close()


def test_streaming(echo_server):
    _ensure_lib()
    from geektls import Session
    with Session(impersonate="safari_18", insecure_skip_verify=True) as s:
        r = s.get(echo_server + "/stream")
        total = sum(len(c) for c in r.iter_bytes(32768))
        assert total == 64 * 16384
        r.close()


def test_post_body_echo(echo_server):
    _ensure_lib()
    from geektls import Session
    with Session(impersonate="chrome_150", insecure_skip_verify=True) as s:
        r = s.post(echo_server + "/echo", body="hello-geektls")
        body = json.loads(r.read())
        assert body["method"] == "POST"
        assert body["body"] == "hello-geektls"
        r.close()


def test_error_path(echo_server):
    """非法 URL / 不存在预设必须抛结构化错误，不崩进程。"""
    _ensure_lib()
    from geektls import Session, GeekTLSError
    with pytest.raises(GeekTLSError):
        Session(impersonate="no_such_browser")
    with Session(impersonate="chrome_133", insecure_skip_verify=True) as s:
        with pytest.raises(GeekTLSError):
            s.get("http://127.0.0.1:1/echo")  # P3 只支持 https


def _profile_without_ech(name="chrome_133"):
    """describe_preset 取预设并剥 ECH——bogdanfinn H3 服务端不接受 QUIC hello
    里的 ECH 扩展（服务端兼容面限制，与真 Chrome 无关；见 p4 capability 文档）。"""
    _ensure_lib()
    from geektls import _ffi
    p = _ffi.take_json(_ffi.lib.gtls_describe_preset(name.encode()))
    p["tls"]["detail"]["extensions"] = [
        e for e in p["tls"]["detail"]["extensions"] if e["type"] != 65037]
    return p


def test_h3_forced(echo_server):
    """force_http3：QUIC+H3 直连本地 echo（同端口 UDP）。"""
    _ensure_lib()
    from geektls import Session
    with Session(profile=_profile_without_ech(), insecure_skip_verify=True) as s:
        r = s.get(echo_server + "/echo", force_http3=True, timeout_ms=5000)
        assert r.status == 200
        assert r.used_protocol == "h3"
        body = json.loads(r.read())
        assert body["proto"] == "HTTP/3.0"
        r.close()


def test_h3_alt_svc_upgrade(echo_server):
    """Alt-Svc 学习：首个请求走 h2 并学到 h3 能力，第二个请求升级 H3。"""
    _ensure_lib()
    from geektls import Session
    with Session(profile=_profile_without_ech(), insecure_skip_verify=True) as s:
        r1 = s.get(echo_server + "/echo")
        assert r1.used_protocol == "h2"  # 首访无 Alt-Svc 记录
        r1.close()
        r2 = s.get(echo_server + "/echo")
        assert r2.used_protocol == "h3"  # Alt-Svc 已学习 → 升级
        r2.close()
