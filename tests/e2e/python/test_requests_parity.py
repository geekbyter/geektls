"""requests 对齐 + 明文档（G5）的 e2e：本地明文 HTTP 服务端，零外部依赖。

为什么用明文服务端而不是复用 Go echo-server：这些断言全是**绑定层语义**
（cookie jar / auth / 重定向开关 / 表单编码），跟 TLS 指纹无关；走 http:// 顺带把
G5 的明文档链路一起覆盖了（两件事一次验完，且不依赖 echo-server 的端点扩展）。

覆盖：cookies（会话 jar / 响应 jar / 显式头优先 / 请求级覆盖）、timeout 元组、
auth Basic、请求级 allow_redirects / max_redirects、data=list[tuple] 表单、
proxies 按 scheme 选、http:// 明文请求（selfcheck 为零值）、HTTPError、
asyncio 视图新增的透传（header/elapsed/iter_content）。
"""

import asyncio
import base64
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))


def _ensure_lib():
    if os.sys.platform == "win32":
        name = "geektls.dll"
    elif os.sys.platform == "darwin":
        name = "libgeektls.dylib"
    else:
        name = "libgeektls.so"
    os.environ.setdefault("GEEDTLS_LIB", os.path.join(ROOT, "build", name))
    if os.path.join(ROOT, "bindings", "python") not in os.sys.path:
        os.sys.path.insert(0, os.path.join(ROOT, "bindings", "python"))


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _read_body(self):
        # BaseHTTPRequestHandler 不替你解 chunked：流式上传（iter body）走的是
        # Transfer-Encoding: chunked，这里手动收（也顺便验证引擎真的在 chunked）。
        if (self.headers.get("Transfer-Encoding") or "").lower() == "chunked":
            out = []
            while True:
                line = self.rfile.readline().strip()
                size = int(line.split(b";")[0] or b"0", 16)
                if size == 0:
                    self.rfile.readline()  # 末尾 CRLF
                    break
                out.append(self.rfile.read(size))
                self.rfile.read(2)  # 块间 CRLF
            return b"".join(out)
        n = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(n) if n else b""

    def _send(self, code, body=b"", headers=(), ctype="text/plain"):
        self.send_response(code)
        if ctype:
            self.send_header("Content-Type", ctype)
        for k, v in headers:
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _cookie_auth(self):
        return {"cookies": self.headers.get("Cookie"),
                "auth": self.headers.get("Authorization")}

    def do_GET(self):
        self._read_body()
        if self.path.startswith("/setcookie"):
            self._send(200, b"ok", [("Set-Cookie", "sid=abc; Path=/")])
        elif self.path.startswith("/redirect"):
            self._send(302, b"", [("Location", "/echo")])
        elif self.path.startswith("/echo"):
            self._send(200, json.dumps(self._cookie_auth()).encode(),
                       ctype="application/json")
        else:
            self._send(404, b"nope")

    def do_POST(self):
        body = self._read_body()
        out = {
            "body": body.decode(),
            "ctype": self.headers.get("Content-Type", ""),
            "te": self.headers.get("Transfer-Encoding", ""),
        }
        self._send(200, json.dumps(out).encode(), ctype="application/json")

    def log_message(self, *a):  # 测试输出保持干净
        pass


@pytest.fixture(scope="module")
def plain_server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield "http://127.0.0.1:%d" % srv.server_address[1]
    finally:
        srv.shutdown()
        srv.server_close()


def _session(**kw):
    _ensure_lib()
    from geektls import Session

    kw.setdefault("impersonate", "chrome_133")
    return Session(**kw)


def test_plaintext_http_basic(plain_server):
    """G5：http:// 走 H1、无 TLS ⇒ selfcheck 全空、协议恒 http/1.1。"""
    with _session() as s:
        r = s.get(plain_server + "/echo")
        assert r.status_code == 200 and r.ok
        assert r.used_protocol == "http/1.1"
        sc = r.selfcheck
        assert sc.get("ja3", "") == "" and sc.get("ja4", "") == ""
        assert sc.get("sni_sent", False) is False
        assert json.loads(r.text)["cookies"] is None  # 没带 cookie


def test_cookies_roundtrip_and_precedence(plain_server):
    with _session(cookies={"a": "1"}) as s:
        assert s.get(plain_server + "/echo").json()["cookies"] == "a=1"

        # 服务端 Set-Cookie 自动进 jar（响应视图 + 会话 jar 都有）
        assert dict(s.get(plain_server + "/setcookie").cookies) == {"sid": "abc"}
        assert s.cookies.get("sid") == "abc"

        # 显式 Cookie 头优先：同名用显式值，其它名字仍从 jar 带（引擎合并）
        got = s.get(plain_server + "/echo",
                    headers={"Cookie": "a=EXPLICIT"}).json()["cookies"]
        assert "a=EXPLICIT" in got and "a=1" not in got and "sid=abc" in got

        # 请求级 cookies= 覆盖会话 jar（同名）
        got = s.get(plain_server + "/echo", cookies={"a": "REQ"}).json()["cookies"]
        assert "a=REQ" in got and "a=1" not in got


def test_cookies_types_and_mutation(plain_server):
    _ensure_lib()
    from geektls import Cookies

    with _session(cookies="x=1; y=2") as s:
        got = s.get(plain_server + "/echo").json()["cookies"]
        assert got == "x=1; y=2"
        s.cookies["z"] = "3"
        s.cookies.update({"y": "22"})
        got = s.get(plain_server + "/echo").json()["cookies"]
        assert got == "x=1; y=22; z=3"
        assert s.cookies.get_dict() == {"x": "1", "y": "22", "z": "3"}
        assert isinstance(s.cookies.copy(), Cookies)
        del s.cookies["z"]
        assert "z" not in s.cookies.get_dict()


def test_timeout_tuple(plain_server):
    with _session(timeout=(1, 0.5)) as s:  # (connect, read)
        assert s.get(plain_server + "/echo").status_code == 200
    with _session(timeout=1.5) as s:  # 单值仍然可用
        assert s.get(plain_server + "/echo").status_code == 200
    with pytest.raises(ValueError):
        _session(timeout=(1, 2, 3))
    with pytest.raises(ValueError):
        _session(timeout="abc")


def test_auth_basic(plain_server):
    want = "Basic " + base64.b64encode(b"u:p").decode()
    with _session(auth=("u", "p")) as s:
        assert s.get(plain_server + "/echo").json()["auth"] == want
        # 自己给的 Authorization 头优先（不做覆盖）
        got = s.get(plain_server + "/echo",
                    headers={"Authorization": "Bearer t"}).json()["auth"]
        assert got == "Bearer t"
        # 请求级 auth 覆盖会话级
        got = s.get(plain_server + "/echo", auth=("x", "y")).json()["auth"]
        assert got == "Basic " + base64.b64encode(b"x:y").decode()
    with pytest.raises(ValueError):
        _session(auth="just-a-string")


def test_redirect_control(plain_server):
    _ensure_lib()
    from geektls import GeekTLSError

    with _session() as s:
        assert s.get(plain_server + "/redirect").status_code == 200  # 默认跟随
        assert s.get(plain_server + "/redirect", allow_redirects=False).status_code == 302
        with pytest.raises(GeekTLSError):
            s.get(plain_server + "/redirect", max_redirects=0)
    with _session(allow_redirects=False) as s:  # 会话级
        assert s.get(plain_server + "/redirect").status_code == 302


def test_data_list_of_pairs_is_form(plain_server):
    """list[tuple] 是表单（requests 语义），不是 chunked 流式 body。"""
    with _session() as s:
        out = s.post(plain_server + "/form", data=[("a", "1"), ("a", "2")]).json()
        assert out["body"] == "a=1&a=2"
        assert out["ctype"].startswith("application/x-www-form-urlencoded")
        assert out["te"] == ""
        # 生成器仍然走 chunked 流式上传（旧行为不变）
        out = s.post(plain_server + "/form", data=iter([b"chunk1", b"chunk2"])).json()
        assert out["body"] == "chunk1chunk2"
        assert out["te"] == "chunked"


def test_proxies_pick_by_scheme():
    _ensure_lib()
    from geektls import _pick_proxy

    p = {"http": "http://p-http:1", "https": "http://p-https:2", "all": "http://p-all:3"}
    assert _pick_proxy(p, "http") == "http://p-http:1"
    assert _pick_proxy(p, "https") == "http://p-https:2"
    assert _pick_proxy({"all": "http://p-all:3"}, "http") == "http://p-all:3"


def test_http_error_type(plain_server):
    _ensure_lib()
    from geektls import GeekTLSError, HTTPError

    with _session() as s:
        r = s.get(plain_server + "/missing")
        assert r.status_code == 404 and not r.ok
        with pytest.raises(HTTPError) as ei:
            r.raise_for_status()
        assert isinstance(ei.value, GeekTLSError)  # 子类：旧 except 仍能捕获
        assert ei.value.response is r


def test_async_view_passthrough(plain_server):
    _ensure_lib()
    from geektls.asyncio import AsyncSession

    async def go():
        async with AsyncSession(impersonate="chrome_133") as s:
            r1 = await s.get(plain_server + "/echo")
            assert r1.header("content-type").startswith("application/json")
            assert r1.elapsed is not None and r1.elapsed >= 0
            body = await r1.content()
            r2 = await s.get(plain_server + "/echo")
            chunks = [c async for c in r2.iter_content(8)]
            assert b"".join(chunks) == body

    asyncio.run(go())
