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


def test_decompress_matrix(echo_server):
    """T-DECOMP：六种编码路径全部透明解压；headers 保留线上原值。"""
    _ensure_lib()
    from geektls import Session
    expect = ("geektls-decompress-check," * 400 + "END").encode()
    with Session(impersonate="chrome_133", insecure_skip_verify=True) as s:
        for path in ("/gzip", "/deflate", "/deflate-raw", "/br", "/zstd", "/multi"):
            r = s.get(echo_server + path)
            assert r.status == 200, path
            assert r.decoded, path
            assert r.content_encoding, path
            assert r.headers.get("content-encoding"), path  # 线上原值不篡改
            assert r.content == expect, path
            r.close()
        # 未知编码：原样透传 + warning
        r = s.get(echo_server + "/x-enc")
        assert r.content == expect and not r.decoded and r.warnings
        r.close()
        # 请求级关闭：拿到 gzip 原字节
        r = s.get(echo_server + "/gzip", auto_decompress=False)
        assert not r.decoded and r.content[:2] == b"\x1f\x8b"
        r.close()


def test_websocket(echo_server):
    """wss echo：握手（指纹链路+受控头序）、text/binary echo、close。"""
    _ensure_lib()
    from geektls import Session, WebSocket
    ws_url = echo_server.replace("https://", "wss://") + "/ws"
    with Session(impersonate="chrome_133", insecure_skip_verify=True) as s:
        with s.websocket(ws_url) as ws:
            ws.send("hello-ws")
            op, data = ws.recv(timeout=5)
            assert op == WebSocket.OP_TEXT and data == b"hello-ws"
            ws.send(b"\x00\x01\xffbinary", WebSocket.OP_BINARY)
            op, data = ws.recv(timeout=5)
            assert op == WebSocket.OP_BINARY and data == b"\x00\x01\xffbinary"
            # ping → 服务端回 pong（我们的 recv 吞 pong 前会回；直接收 data）
            ws.send(b"probe", WebSocket.OP_PING)
            ws.send("after-ping")
            op, data = ws.recv(timeout=5)
            assert op == WebSocket.OP_TEXT and data == b"after-ping"
        # close 后 handle 失效
        assert ws._handle == 0


def test_asyncio_api(echo_server):
    """asyncio 包装层（to_thread 线程池异步）：get/流式/并发。"""
    import asyncio
    _ensure_lib()
    from geektls.asyncio import AsyncSession

    async def main():
        async with AsyncSession(impersonate="chrome_133", insecure_skip_verify=True) as s:
            r = await s.get(echo_server + "/echo")
            assert r.status_code == 200 and r.selfcheck["ja3"]
            await r.close()
            # 流式
            r = await s.get(echo_server + "/stream")
            total = 0
            async for chunk in r.iter_bytes(32768):
                total += len(chunk)
            assert total == 64 * 16384
            await r.close()
            # 并发 20 请求
            rs = await asyncio.gather(*[s.get(echo_server + "/echo") for _ in range(20)])
            for r in rs:
                assert r.status_code == 200
                await r.close()
    asyncio.run(main())


def _profile_without_ech(name="chrome_133"):
    """describe_preset 取预设并剥 ECH——bogdanfinn H3 服务端不接受 QUIC hello
    里的 ECH 扩展（服务端兼容面限制，与真 Chrome 无关；见 p4 capability 文档）。"""
    _ensure_lib()
    from geektls import _ffi
    p = _ffi.take_json(_ffi.lib.gtls_describe_preset(name.encode()))
    p["tls"]["detail"]["extensions"] = [
        e for e in p["tls"]["detail"]["extensions"] if e["type"] != 65037]
    return p


def test_module_level_helpers(echo_server):
    """模块级快捷 API（requests 风格）：共享默认会话首次可配置、之后只读。"""
    _ensure_lib()
    import geektls
    s = geektls.default_session(impersonate="chrome_133", verify=False)
    assert s is geektls.default_session()
    with pytest.raises(ValueError):
        geektls.default_session(impersonate="chrome_150")
    r = geektls.get(echo_server + "/echo", params={"k": "v"})
    assert r.status == 200
    assert json.loads(r.read())["method"] == "GET"
    r.close()
    r = geektls.post(echo_server + "/echo", data="hi")
    body = json.loads(r.read())
    assert body["method"] == "POST" and body["body"] == "hi"
    r.close()


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
    """Alt-Svc 学习：首个请求走 h2 并学到 h3 能力，第二个请求升级 H3。

    注意：G8 起 H3 必须显式开启（protocols / h3=True），默认集合只有 h1.1+h2。
    """
    _ensure_lib()
    from geektls import Session
    with Session(profile=_profile_without_ech(), insecure_skip_verify=True, h3=True) as s:
        r1 = s.get(echo_server + "/echo")
        assert r1.used_protocol == "h2"  # 首访无 Alt-Svc 记录
        r1.close()
        r2 = s.get(echo_server + "/echo")
        assert r2.used_protocol == "h3"  # Alt-Svc 已学习 → 升级
        r2.close()


def test_tls_option_mapping():
    """verify / cert 归一（纯函数层，不依赖动态库）：requests 风格取值 → 会话选项。

    重点是"配了 CA 就不可能被静默丢掉"：非 bool 且非路径/PEM 的取值必须报错。
    """
    _ensure_lib()
    import geektls
    from pathlib import Path

    PEM = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"
    cases = [
        (None, {}),
        (True, {}),
        (False, {"insecure_skip_verify": True}),
        ("/x/ca.pem", {"ca_bundle": "/x/ca.pem"}),
        (b"/x/ca.pem", {"ca_bundle": "/x/ca.pem"}),
        (PEM, {"ca_bundle": PEM}),
        (Path("/x/ca.dir"), {"ca_bundle": str(Path("/x/ca.dir"))}),
    ]
    for value, expect in cases:
        opts = {}
        geektls._apply_verify(opts, value)
        assert opts == expect, (value, opts, expect)
    for bad in ("", "   ", 123, 1.5, [], {}, object()):
        with pytest.raises(ValueError):
            geektls._apply_verify({}, bad)

    opts = {}
    geektls._apply_cert(opts, "/x/c.pem", None)
    assert opts == {"client_cert": "/x/c.pem"}          # 证书+私钥可同文件
    opts = {}
    geektls._apply_cert(opts, ("/x/c.pem", "/x/c.key"), None)
    assert opts == {"client_cert": "/x/c.pem", "client_key": "/x/c.key"}
    opts = {}
    geektls._apply_cert(opts, ("/x/c.pem", None), None)  # requests 允许 key 位为 None
    assert opts == {"client_cert": "/x/c.pem"}
    opts = {}
    geektls._apply_cert(opts, b"-----BEGIN CERTIFICATE-----\nAA==\n-----END",
                        b"-----BEGIN PRIVATE KEY-----\nAA==\n-----END")
    assert set(opts) == {"client_cert", "client_key"}
    opts = {}
    geektls._apply_cert(opts, None, "/x/k.pem")   # 只给私钥：交给引擎报错，不静默丢
    assert opts == {"client_key": "/x/k.pem"}
    for bad in [("", None), (123, None), ([], None), ({}, None),
                (None, 123), ("/x/c.pem", 123)]:
        with pytest.raises(ValueError):
            geektls._apply_cert({}, *bad)
    with pytest.raises(ValueError):  # 加密私钥不支持
        geektls._apply_cert({}, ("/x/c.pem", "/x/c.key", "secret"), None)


def test_tls_options_are_session_scoped(echo_server):
    """verify / cert 只能在 Session(...) 给；传到 request() 要明确报错而非静默失效。"""
    _ensure_lib()
    from geektls import Session
    with Session(impersonate="chrome_133", verify=False) as s:
        for kw in ({"verify": False}, {"verify": "/x/ca.pem"},
                   {"cert": "/x/c.pem"}, {"cert_key": "/x/c.key"}):
            with pytest.raises(ValueError):
                s.get(echo_server + "/echo", **kw)


def _read_timeout_supported(s, echo_server) -> bool:
    """能力探测：新引擎把 request_json 严格解析成 engine.Request。

    给 ``read_timeout_ms`` 传字符串 ⇒ 认识该字段的 core 在 unmarshal 时报错；
    旧构建（不含该字段）会当成未知键静默跳过，请求照常成功。
    """
    import geektls  # 本模块只在用例内部 import（包路径由 _ensure_lib 准备）

    try:
        r = s.request("GET", echo_server + "/echo", read_timeout_ms="not-an-int")
    except geektls.GeekTLSError:
        return True
    r.close()
    return False


def test_a6_read_timeout(echo_server):
    """A6：body 空闲读超时（会话级 read_timeout / 请求级 read_timeout_ms）。

    超时必须是结构化错误、必须在毫秒级把调用线程放出来，并且取消要真的传到
    服务端（/stall 的 handler 因连接被作废而提前结束）。
    """
    _ensure_lib()
    import geektls
    from geektls import Session, GeekTLSError

    with Session(impersonate="chrome_133", verify=False) as probe:
        if not _read_timeout_supported(probe, echo_server):
            pytest.skip("build/geektls.dll 是旧构建（不认 read_timeout_ms），"
                        "重建动态库后再跑本用例")

    # 会话级：1.2s 内拿到 read_timeout，而不是等 /stall 的 5s
    with Session(impersonate="chrome_133", verify=False, read_timeout=1.2) as s:
        r = s.get(echo_server + "/stall")
        t0 = time.monotonic()
        with pytest.raises(GeekTLSError) as ei:
            r.content
        dt = time.monotonic() - t0
        r.close()
        assert ei.value.code == "read_timeout", ei.value.code
        assert 1.0 <= dt < 3.0, dt

    # 请求级覆盖会话级（会话不给超时，请求给 300ms）
    with Session(impersonate="chrome_133", verify=False) as s:
        r = s.get(echo_server + "/stall", read_timeout_ms=300)
        t0 = time.monotonic()
        with pytest.raises(GeekTLSError) as ei:
            r.content
        dt = time.monotonic() - t0
        assert ei.value.code == "read_timeout"
        assert dt < 2.0, dt
        # 超时之后连接作废：再读还是同一个错误，不会退回"无限等待"
        with pytest.raises(GeekTLSError) as ei2:
            r.content
        assert ei2.value.code == "read_timeout"
        r.close()

    # 默认不设 read_timeout ⇒ /stall 的 5s 挂死会完整读完（行为零改变）
    with Session(impersonate="chrome_133", verify=False, timeout=30) as s:
        r = s.get(echo_server + "/stall")
        body = r.content
        r.close()
        assert len(body) > 1024


# 192.0.2.0/24 是 TEST-NET-1：不参与 DNS、也不可路由，用来当"绝不该连上"的目标。
_A8_TARGET = "https://192.0.2.1:443/"
_A8_DEAD_PROXY = "socks5://127.0.0.1:1"  # 端口 1 上没有监听，只是占位


def _a8_env(monkeypatch):
    """把代理环境变量钉成确定状态（否则机器上已有的 HTTPS_PROXY 会干扰）。"""
    for k in ("HTTPS_PROXY", "https_proxy", "NO_PROXY", "no_proxy", "HTTP_PROXY", "http_proxy"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("ALL_PROXY", _A8_DEAD_PROXY)


def _a8_force_h3_err(**session_kwargs):
    """force_http3 + 经环境变量派生的代理 ⇒ 拨号前就该拿到的错误。

    判据不依赖真代理：QUIC 过 HTTP 代理需要 CONNECT-UDP（本库未实现），所以
    "代理确实生效"这件事会在拨号前以 force_http3 冲突的形式暴露出来；不打网络。
    """
    import geektls
    from geektls import Session

    with Session(impersonate="chrome_133", verify=False, timeout=2, **session_kwargs) as s:
        try:
            s.request("GET", _A8_TARGET, force_http3=True)
        except geektls.GeekTLSError as e:
            return e
    raise AssertionError("请求不该成功")


def _a8_env_marker(err) -> bool:
    s = str(err)
    return "force_http3" in s and "代理" in s


def _a8_require_env(monkeypatch):
    """正向对照：环境变量派生的代理必须可见，否则是旧构建 ⇒ skip 而不是假通过。"""
    _ensure_lib()
    _a8_env(monkeypatch)
    if not _a8_env_marker(_a8_force_h3_err()):
        pytest.skip("动态库不读代理环境变量（旧构建），重建后再跑本用例")


def test_a8_proxy_from_env(monkeypatch):
    """A8：不显式给 proxy 时读 HTTPS_PROXY/ALL_PROXY，`trust_env=False` 关掉。"""
    _a8_require_env(monkeypatch)

    # trust_env=False ⇒ 环境变量派生的代理不参与，于是走直连（打不可路由地址而失败）
    e2 = _a8_force_h3_err(trust_env=False)
    assert not _a8_env_marker(e2), str(e2)

    # 显式 proxy 优先于 trust_env=False（curl 的 --proxy 就是硬要求）
    import geektls
    from geektls import Session
    monkeypatch.delenv("ALL_PROXY")
    with Session(impersonate="chrome_133", verify=False, timeout=2,
                 proxy=_A8_DEAD_PROXY, trust_env=False) as s:
        with pytest.raises(geektls.GeekTLSError) as ei:
            s.request("GET", _A8_TARGET, force_http3=True)
        assert _a8_env_marker(ei.value), str(ei.value)


def test_a8_no_proxy_and_loopback(monkeypatch, echo_server):
    """A8：NO_PROXY 命中与回环目标都不该被环境变量派生的代理劫走。"""
    _a8_require_env(monkeypatch)

    # 同一环境，加上 NO_PROXY 之后代理就不再命中（正向对照刚验过，这里只验反向）
    monkeypatch.setenv("NO_PROXY", "192.0.2.0/24")
    assert not _a8_env_marker(_a8_force_h3_err())

    # 回环目标（echo server 就在 127.0.0.1）即使 ALL_PROXY 指向黑洞也必须能直连
    monkeypatch.delenv("NO_PROXY", raising=False)
    from geektls import Session
    with Session(impersonate="chrome_133", verify=False, timeout=5) as s:
        r = s.get(echo_server + "/echo")
        assert r.status_code == 200
        r.close()


# --- A9：地址控制（resolve / local_address / ip_version）---------------------
# 判据都挑"不需要真 DNS、不打外网"的形态。旧构建不认识这三项 ⇒ 用正向对照
# 探测，探测不过就 skip，不会假通过。

_A9_NAME = "pinned.example"  # 不可解析也不该被解析：能连通就只能是因为钉位
_A9_DEAD_IP = "192.0.2.9"    # TEST-NET-1：本机没有这个源地址


def _a9_new_err(**session_kwargs) -> str:
    """建会话时的错误文本（引擎在 NewSession 里就校验这三项）；无错误返回 ""。"""
    import geektls
    from geektls import Session
    try:
        s = Session(impersonate="chrome_133", verify=False, timeout=3, **session_kwargs)
    except geektls.GeekTLSError as e:
        return str(e)
    s.close()
    return ""


def _a9_require_net():
    """正向对照：ip_version 的非法值必须在建会话时被拒。"""
    _ensure_lib()
    if "ip_version" not in _a9_new_err(ip_version="7"):
        pytest.skip("动态库不认 resolve/local_address/ip_version（旧构建），重建后再跑本用例")


def test_a9_net_control_validated():
    """A9：非法/自相冲突的地址控制在建会话时就报错，而不是留到拨号。"""
    _a9_require_net()
    assert "ip_version" in _a9_new_err(ip_version="7")
    assert "local_address" in _a9_new_err(local_address="eth0")     # 网卡名不支持
    assert "IP" in _a9_new_err(resolve={_A9_NAME: "not-an-ip"})     # 值必须是字面量
    # 绑定地址与族偏好互相矛盾 ⇒ 每次拨号都会失败，提前拒
    assert "冲突" in _a9_new_err(local_address="10.0.0.1", ip_version="6")
    assert "冲突" in _a9_new_err(resolve={_A9_NAME: "::1"}, ip_version="4")
    # 合法形态不报错（几种写法都认）
    assert _a9_new_err(ip_version="ipv4") == ""
    assert _a9_new_err(resolve={_A9_NAME + ":443": "127.0.0.1"}) == ""


def test_a9_resolve_pins_target_but_keeps_sni_and_host(echo_server):
    """A9：域名钉到 127.0.0.1 能连通，而 Host / SNI / 指纹仍是原域名。"""
    _a9_require_net()
    from geektls import Session
    host, _, port = echo_server.rpartition(":")
    assert host, echo_server
    url = "https://%s:%s/echo" % (_A9_NAME, port)

    with Session(impersonate="chrome_133", verify=False, timeout=5,
                 resolve={_A9_NAME: "127.0.0.1"}) as s:
        r = s.get(url)
        assert r.status_code == 200, r.status_code
        body = r.json()
        r.close()
    # 钉位只改"连到哪"：Host/:authority 仍是原域名
    assert body["host"] == "%s:%s" % (_A9_NAME, port), body
    assert body["path"] == "/echo"
    # 实际连的是 IP，但 SNI 不能因此掉线（那会改 JA4 的 d/i 标志）
    assert r.selfcheck.get("sni_sent") is True, r.selfcheck

    # host:port 形态的键优先于 host 形态（curl --resolve 同规则）
    with Session(impersonate="chrome_133", verify=False, timeout=5,
                 resolve={_A9_NAME + ":" + port: "127.0.0.1"}) as s:
        assert s.get(url).status_code == 200


def test_a9_ip_version_and_local_address(echo_server):
    """A9：ip_version 收窄族；local_address 真的落到 socket 上（绑不上就失败）。"""
    _a9_require_net()
    from geektls import Session

    # 回环目标是 IPv4 ⇒ v6 偏好必须在拨号前给出可读错误
    with Session(impersonate="chrome_133", verify=False, timeout=3,
                 ip_version="6") as s:
        import geektls
        with pytest.raises(geektls.GeekTLSError) as ei:
            s.get(echo_server + "/echo")
        assert "同族" in str(ei.value) or "ip_version" in str(ei.value), str(ei.value)

    with Session(impersonate="chrome_133", verify=False, timeout=5,
                 ip_version="4") as s:
        assert s.get(echo_server + "/echo").status_code == 200

    # 绑本机有的源地址（回环）可用；绑不存在的地址必须失败——不能"绑不上当没绑"
    with Session(impersonate="chrome_133", verify=False, timeout=5,
                 local_address="127.0.0.1") as s:
        assert s.get(echo_server + "/echo").status_code == 200
    import geektls
    with Session(impersonate="chrome_133", verify=False, timeout=3,
                 local_address=_A9_DEAD_IP) as s:
        with pytest.raises(geektls.GeekTLSError):
            s.get(echo_server + "/echo")


def test_a9_force_h3_blocked_by_net_control():
    """A9：地址控制没接进 QUIC 拨号 ⇒ force_http3 明确报错，不偷偷绕过那一项。"""
    _a9_require_net()
    import geektls
    from geektls import Session
    for kw in ({"resolve": {_A9_NAME: "127.0.0.1"}},
               {"local_address": "127.0.0.1"},
               {"ip_version": "4"}):
        field = list(kw)[0]
        with Session(impersonate="chrome_133", verify=False, timeout=3, **kw) as s:
            with pytest.raises(geektls.GeekTLSError) as ei:
                s.request("GET", "https://%s:443/echo" % _A9_NAME, force_http3=True)
            msg = str(ei.value)
            assert "force_http3" in msg and field in msg, msg


def test_a9_session_options_rejected_at_request_level():
    """会话级选项写到请求上必须报错：引擎忽略未知字段，静默失效比报错难查。"""
    _ensure_lib()
    import geektls
    from geektls import Session
    with Session(impersonate="chrome_133", verify=False) as s:
        for kw in ({"resolve": {_A9_NAME: "127.0.0.1"}}, {"ip_version": "4"},
                   {"trust_env": False}, {"cookies": True}):
            with pytest.raises(ValueError) as ei:
                s.request("GET", "https://%s/echo" % _A9_NAME, **kw)
            assert list(kw)[0] in str(ei.value)


def test_a9_unknown_session_option_rejected():
    """拼错的会话级选项必须报错：引擎忽略未知字段，静默失效会让"以为钉了位"变成没钉。"""
    _ensure_lib()
    from geektls import Session
    for kw in ({"local_addr": "127.0.0.1"}, {"resolveAll": True}, {"proxie": "http://x:1"}):
        with pytest.raises(ValueError) as ei:
            Session(impersonate="chrome_133", verify=False, **kw)
        assert list(kw)[0] in str(ei.value)
