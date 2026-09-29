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


def _lib_name():
    """默认动态库名（平台感知）：此前硬编码 geektls.dll，在 Linux/macOS 上只能靠
   外部设 GEEDTLS_LIB 才能跑，属于"在我机器上能跑"的坑。"""
    if os.sys.platform == "win32":
        return "geektls.dll"
    return "libgeektls.dylib" if os.sys.platform == "darwin" else "libgeektls.so"


def _server_name():
    return "echo-server.exe" if os.sys.platform == "win32" else "echo-server"


def _ensure_lib():
    os.environ.setdefault("GEEDTLS_LIB", os.path.join(ROOT, "build", _lib_name()))
    if os.path.join(ROOT, "bindings", "python") not in os.sys.path:
        os.sys.path.insert(0, os.path.join(ROOT, "bindings", "python"))


@pytest.fixture(scope="session")
def echo_server():
    exe = os.path.join(ROOT, "build", _server_name())
    if not os.path.exists(exe):
        pytest.skip("%s not built (go build ./cmd/echo-server in tests/e2e)" % _server_name())
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
    import re
    assert re.fullmatch(r"\d+\.\d+\.\d+", v["core"])


def test_version_sources_agree(presets):
    """绑定 __version__ 必须等于动态库 gtls_version()["core"]。

    `bindings/python/geektls/__init__.py` 的 `__version__` 是**第 4 处**版本字面量——
    0.1.4 及之前的发布清单只写了三处（core / pyproject.toml / package.json），漏了它。
    四处的静态一致性由 ci.yml 的 "version literals must agree" 步守住；这条再从运行期
    确认"包内声明的版本 == 包内动态库导出的版本"（防止换了库却没同步声明）。
    """
    _ensure_lib()
    import geektls
    v = geektls.version()
    assert geektls.__version__ == v["core"], (
        "绑定 __version__=%r 与动态库 core=%r 不一致（两处都要改）"
        % (geektls.__version__, v["core"])
    )


def test_preset_matrix_echo(echo_server, presets):
    """全预设：GET /echo 200 + selfcheck 结构合法 + JA4 格式正确。"""
    _ensure_lib()
    from geektls import Session
    for name in presets:
        with Session(impersonate=name, insecure_skip_verify=True) as s:
            r = s.get(echo_server + "/echo")
            assert r.status == 200, name
            # TLS1.2-era 预设（chrome_38/IE/curl 等）无 h2 ALPN，合法落到 http/1.1
            assert r.used_protocol in ("h2", "http/1.1"), name
            sc = r.selfcheck
            assert len(sc["ja3_hash"]) == 32, name
            parts = sc["ja4"].split("_")
            # echo server 是 127.0.0.1（IP 字面量）：线上省略 SNI，ja4_a 的
            # SNI 标志位（协议符 + 2 位版本之后，index 3）为 i；版本可以是 12/13
            a = parts[0]
            assert len(parts) == 3 and a[0] in "tq" and a[3] == "i", (name, sc["ja4"])
            body = json.loads(r.read())
            assert body["proto"] in ("HTTP/2.0", "HTTP/1.1"), name
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


def test_stream_upload_chunked(echo_server):
    """迭代器 body → 流式上传（H1 chunked / H2 DATA）；echo 回显拼接一致。"""
    _ensure_lib()
    from geektls import Session

    def gen():
        yield "hello"
        yield b",py-stream"
        yield ""  # 空块是 no-op

    with Session(impersonate="chrome_133", insecure_skip_verify=True) as s:
        r = s.post(echo_server + "/echo", body=gen())
        assert r.status == 200
        body = json.loads(r.read())
        assert body["body"] == "hello,py-stream"
        r.close()


def test_selfcheck_extended_fields(echo_server):
    """T3 深化字段：存在性 + ja3_fullstring 与 ja3_hash 自洽 + IP 目标 sni_sent=False。"""
    import hashlib
    _ensure_lib()
    from geektls import Session
    with Session(impersonate="chrome_133", insecure_skip_verify=True) as s:
        r = s.get(echo_server + "/echo")
        sc = r.selfcheck
        assert sc["ja3_fullstring"] == sc["ja3"]
        assert hashlib.md5(sc["ja3_fullstring"].encode()).hexdigest() == sc["ja3_hash"]
        assert sc["sni_sent"] is False  # echo 是 127.0.0.1（IP 字面量）
        assert len(sc["wire_extensions"]) > 0 and len(sc["extensions"]) > 0
        assert 0 not in sc["wire_extensions"]  # SNI 未上链
        assert len(sc["grease"]) > 0  # chrome 必有 GREASE 标记
        assert sc["negotiated"]["alpn"] == "h2"
        assert sc["negotiated"]["version"] == "0x0304"
        r.close()


def test_connection_pool_reuse(echo_server):
    """连接池（默认开）：chrome_133 扩展洗牌 ⇒ 同连接 JA3 恒定；
    两次请求 ja3_hash 相等即证明复用了同一条连接（未发新 ClientHello）。"""
    _ensure_lib()
    from geektls import Session
    with Session(impersonate="chrome_133", insecure_skip_verify=True) as s:
        r1 = s.get(echo_server + "/echo")
        h1 = r1.selfcheck["ja3_hash"]
        r1.close()
        r2 = s.get(echo_server + "/echo")
        assert r2.selfcheck["ja3_hash"] == h1
        r2.close()


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
