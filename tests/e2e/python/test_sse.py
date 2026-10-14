"""SSE（text/event-stream）解析的 e2e：本地服务端，零外部依赖。

覆盖：多行 data / event / id / retry / 注释、``\\r\\n`` 与 ``\\r`` 行分隔、事件被
拆到多个 chunk、空 data 不派发、``Last-Event-ID`` 头、``Session.sse`` 与
``Response.iter_sse`` 两条路径。
"""

import os
import threading
import time
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


_ensure_lib()
import geektls  # noqa: E402

BODY = (
    b": keep-alive\r\n"
    b"\r\n"
    b"data: hello\n\n"
    b"event: ping\n"
    b"data: line1\ndata: line2\n\n"
    b"id: 42\n"
    b"data: with-id\n\n"
    b"retry: 3000\n\n"
    b"data:no-space\n\n"
    b"data:  two-spaces\n\n"
    b"data: cr-only\rd: bogus\r\r"
    b"data: final\n\n"
)

# (event, data, id, retry)
EXPECT = [
    ("", "hello", None, None),
    ("ping", "line1\nline2", None, None),
    ("", "with-id", "42", None),
    ("", "no-space", "42", 3000),
    ("", " two-spaces", "42", 3000),
    ("", "cr-only", "42", 3000),
    ("", "final", "42", 3000),
]


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        if self.path.startswith("/sse"):
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            for i in range(0, len(BODY), 7):
                chunk = BODY[i:i + 7]
                self.wfile.write(b"%x\r\n%s\r\n" % (len(chunk), chunk))
                self.wfile.flush()
                time.sleep(0.002)
            self.wfile.write(b"0\r\n\r\n")
            self.wfile.flush()
        elif self.path.startswith("/last"):
            lei = self.headers.get("Last-Event-ID", "-")
            payload = ("data: last=%s\n\n" % lei).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    def log_message(self, *a):
        pass


@pytest.fixture()
def sse_base():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield "http://127.0.0.1:%d" % srv.server_address[1]
    srv.shutdown()


def _session():
    return geektls.Session(impersonate="chrome_154_windows")


def test_session_sse(sse_base):
    with _session() as s:
        events = list(s.sse(sse_base + "/sse"))
    assert [(e.event, e.data, e.id, e.retry) for e in events] == EXPECT


def test_iter_sse_direct(sse_base):
    with _session() as s:
        r = s.get(sse_base + "/sse")
        events = [(e.event, e.data, e.id, e.retry) for e in r.iter_sse()]
    assert events == EXPECT


def test_last_event_id(sse_base):
    with _session() as s:
        events = list(s.sse(sse_base + "/last", last_event_id="777"))
    assert [e.data for e in events] == ["last=777"]


def test_sse_event_repr():
    ev = geektls.SSEEvent("ping", "x", "1", 100)
    assert "ping" in repr(ev)
