"""geektls Python 绑定（ctypes，零编译依赖）。

requests 风格 API；响应体流式（iter_bytes/iter_lines）。
"""

from __future__ import annotations

import base64
import json

from . import _ffi
from .errors import GeekTLSError

__all__ = ["Session", "Response", "version", "init", "last_error", "GeekTLSError"]

EXPECTED_ABI = 1


def _check_error():
    err = _ffi.last_error()
    raise GeekTLSError(err.get("code", "unknown"), err.get("message", "unknown ffi error"))


def version() -> dict:
    """返回 {"abi","core","utls"} 并核对 ABI 主版本（防绑定与动态库错配）。"""
    v = _ffi.take_json(_ffi.lib.gtls_version())
    if v is None:
        _check_error()
    if v.get("abi") != EXPECTED_ABI:
        raise RuntimeError(
            "geektls ABI mismatch: binding expects %d, core exports %r"
            % (EXPECTED_ABI, v.get("abi"))
        )
    return v


def init(options: dict = None) -> None:
    """全局初始化（幂等）。"""
    payload = json.dumps(options or {}).encode()
    if _ffi.lib.gtls_init(payload) != 0:
        _check_error()


def last_error() -> dict:
    """当前线程最近错误；无错误返回 {}。"""
    return _ffi.last_error()


class Response:
    """响应：头部在构造时可用，body 流式。"""

    def __init__(self, handle: int):
        self._handle = handle
        info = _ffi.take_json(_ffi.lib.gtls_response_info(handle))
        if info is None:
            _check_error()
        self.status = info["status"]
        self.headers = [(k, v) for k, v in info.get("headers", [])]
        self.used_protocol = info.get("used_protocol", "")
        self.selfcheck = info.get("selfcheck", {})
        self._closed = False

    def iter_bytes(self, chunk_size: int = 65536):
        """流式读 body。"""
        buf = _ffi.ctypes.create_string_buffer(chunk_size)
        while True:
            n = _ffi.lib.gtls_response_read(self._handle, buf, chunk_size)
            if n < 0:
                _check_error()
            if n == 0:
                return
            yield buf.raw[:n]

    def iter_lines(self, chunk_size: int = 65536):
        """按行流式（以 \\n 切分，跨块拼接）。"""
        pending = b""
        for chunk in self.iter_bytes(chunk_size):
            pending += chunk
            while True:
                idx = pending.find(b"\n")
                if idx < 0:
                    break
                yield pending[:idx + 1]
                pending = pending[idx + 1:]
        if pending:
            yield pending

    def read(self) -> bytes:
        """一次性读完 body。"""
        return b"".join(self.iter_bytes())

    def json(self):
        return json.loads(self.read())

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            _ffi.lib.gtls_response_close(self._handle)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass


class Session:
    """指纹伪造会话（requests 风格）。

    Session(impersonate="chrome_150") 或 profile={...} / ja3=... / ja4r=... /
    clienthello_hex=...；会话级 proxy/timeout_ms/redirect_max/cookie_jar/
    insecure_skip_verify 走 options。
    """

    def __init__(self, impersonate: str = None, *, profile: dict = None,
                 ja3: str = None, ja4r: str = None, clienthello_hex: str = None,
                 **options):
        config = {}
        for key, val in (("impersonate", impersonate), ("profile", profile),
                         ("ja3", ja3), ("ja4r", ja4r),
                         ("clienthello_hex", clienthello_hex)):
            if val is not None:
                config[key] = val
        self._client = _ffi.lib.gtls_client_new(json.dumps(config).encode())
        if not self._client:
            _check_error()
        self._session = 0
        try:
            opts = {k: v for k, v in options.items() if v is not None}
            self._session = _ffi.lib.gtls_session_new(
                self._client, json.dumps(opts).encode())
            if not self._session:
                _check_error()
        except BaseException:
            _ffi.lib.gtls_client_close(self._client)
            self._client = 0
            raise

    def request(self, method: str, url: str, headers=None, body=None,
                timeout_ms: int = None, proxy: str = None, **kwargs) -> Response:
        """发请求；body 可为 str/bytes；响应头到达即返回（body 流式）。"""
        payload = {"method": method, "url": url}
        if headers:
            payload["headers"] = [[k, v] for k, v in (
                headers.items() if isinstance(headers, dict) else headers)]
        if body is not None:
            if isinstance(body, str):
                body = body.encode()
            payload["body_b64"] = base64.b64encode(body).decode()
        if timeout_ms:
            payload["timeout_ms"] = timeout_ms
        if proxy:
            payload["proxy"] = proxy
        payload.update(kwargs)

        resp = _ffi.lib.gtls_request(self._session, json.dumps(payload).encode())
        if not resp:
            _check_error()
        return Response(resp)

    def get(self, url: str, **kwargs) -> Response:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs) -> Response:
        return self.request("POST", url, **kwargs)

    def close(self) -> None:
        if self._session:
            _ffi.lib.gtls_session_close(self._session)
            self._session = 0
        if self._client:
            _ffi.lib.gtls_client_close(self._client)
            self._client = 0

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass
