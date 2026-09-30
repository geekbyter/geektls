"""geektls Python 绑定（ctypes，零编译依赖）。

**requests 风格 API**——日常只要这么用：

    from geektls import Session

    with Session(impersonate="chrome_150") as s:
        r = s.get("https://httpbin.org/json")
        print(r.status_code, r.ok)          # 200 True
        print(r.headers["content-type"])    # 大小写不敏感
        print(r.text[:200])                 # 直接当文本用
        print(r.json()["slideshow"])        # 直接当 JSON 用

响应体**按需读取**：`.content` / `.text` / `.json()` 第一次访问时把 body 读完并缓存；
需要边收边处理的大响应才用 `.iter_content(chunk_size)` / `.iter_lines()`（也保留旧名
`iter_bytes`）。

与 requests 的差异（有意为之，写在这里免得踩坑）：

- `verify` / `cert` 是**会话级**设置（引擎只在建会话时接受），要按请求切换请新建一个
  Session；把它们传给 `request()` 会**明确报错**而不是静默忽略。
  `verify` 支持 `True`（系统信任库）/ `False`（跳过校验）/ CA bundle 路径或 PEM 文本；
  `cert` 支持路径、PEM、`(证书, 私钥)` 元组（mTLS）。
- `cookies` 支持 dict / list[tuple] / `"a=1; b=2"` / `Cookies` / bool（bool 只是开关
  引擎 jar）。`Session.cookies` 与 `Response.cookies` 是本绑定维护的 jar：
  `Session.cookies` 每请求渲染成 `Cookie` 头，响应里的 `Set-Cookie` 自动并入。
  引擎自己还管理一层 jar（覆盖重定向中间跳），两者**同名以显式 Cookie 头为准**，
  不会发出两份（引擎侧的合并规则见 `appendCookieHeader`）。
- 超时分两段：`timeout` 管到响应头到达（也接受 requests 的 `(connect, read)` 元组，
  此时 read 落进 `read_timeout_ms`）；body 逐块读取挂死要另给 `read_timeout`
  （秒，会话级或请求级都行）。触发时抛 `GeekTLSError(code="read_timeout")`，本次读取
  已拿到的字节不回滚、连接作废（与 curl / requests 的 read timeout 同语义）。
- `auth=(user, password)`（或带 `username`/`user` + `password` 属性的对象）只做
  HTTP Basic；自己传了 `Authorization` 头时以你的为准。
- `allow_redirects` / `max_redirects` 会话级与请求级都能用（请求级覆盖会话级）。
- `reason` 由状态码在本地映射（RFC 9110 短语），不是服务端原文。
- `proxies` 是 dict 时按**目标 scheme** 选（`{"http": …, "https": …}`，`"all"` 兜底）；
  引擎一次仍只用一个代理 URL。
- 不做（避免"看起来像"）：`files=` / multipart 上传、`history` / `links` /
  `is_redirect`；`r.elapsed` 是 float 秒（不是 `timedelta`）。
"""

from __future__ import annotations

import base64
import codecs
import json as _json
import os
import threading
import time
from collections.abc import Mapping, MutableMapping
from urllib.parse import urlencode

from . import _ffi
from .errors import GeekTLSError, HTTPError, Timeout

__all__ = [
    "Session",
    "Response",
    "WebSocket",
    "Cookies",
    "CaseInsensitiveDict",
    "version",
    "init",
    "last_error",
    "list_presets",
    "describe_preset",
    "check_profile",
    "GeekTLSError",
    "HTTPError",
    "Timeout",
    "__version__",
    # 模块级快捷 API（requests 风格，共享进程级默认会话）
    "default_session",
    "request",
    "get",
    "head",
    "post",
    "put",
    "patch",
    "delete",
    "options",
]

# 包版本与动态库版本是**两个**版本（见 docs/versioning.md）：包内库与包版本锁死，
# 运行时再用 version() 核对 ABI 主版本。
__version__ = "0.1.7"

EXPECTED_ABI = 1

# 状态码 → reason（RFC 9110 常见短语；引擎不上报服务端原文，这里本地映射）。
_REASON = {
    100: "Continue", 101: "Switching Protocols",
    200: "OK", 201: "Created", 202: "Accepted", 204: "No Content", 206: "Partial Content",
    301: "Moved Permanently", 302: "Found", 303: "See Other", 304: "Not Modified",
    307: "Temporary Redirect", 308: "Permanent Redirect",
    400: "Bad Request", 401: "Unauthorized", 403: "Forbidden", 404: "Not Found",
    405: "Method Not Allowed", 406: "Not Acceptable", 408: "Request Timeout",
    409: "Conflict", 410: "Gone", 413: "Payload Too Large", 415: "Unsupported Media Type",
    418: "I'm a teapot", 422: "Unprocessable Entity", 429: "Too Many Requests",
    500: "Internal Server Error", 501: "Not Implemented", 502: "Bad Gateway",
    503: "Service Unavailable", 504: "Gateway Timeout",
}

# 无 charset 声明时的编码兜底顺序（先 utf-8，再中文常见编码，最后 latin-1）。
_FALLBACK_ENCODINGS = ("utf-8", "gb18030")


def _check_error():
    err = _ffi.last_error()
    raise Timeout.from_error(
        GeekTLSError(err.get("code", "unknown"), err.get("message", "unknown ffi error"))
    )


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
    payload = _json.dumps(options or {}).encode()
    if _ffi.lib.gtls_init(payload) != 0:
        _check_error()


def last_error() -> dict:
    """当前线程最近错误；无错误返回 {}。"""
    return _ffi.last_error()


def list_presets() -> list:
    """列出内置预设（含各族与各平台）。"""
    v = _ffi.take_json(_ffi.lib.gtls_list_presets())
    if v is None:
        _check_error()
    return v if isinstance(v, list) else v.get("presets", [])


def describe_preset(name: str) -> dict:
    """查看某个预设的概要（族/版本/平台/证据等级等）。"""
    v = _ffi.take_json(_ffi.lib.gtls_describe_preset(name.encode()))
    if v is None:
        _check_error()
    return v


def check_profile(spec: str) -> dict:
    """校验 profile JSON / JA3 / JA4R 串；返回结构与告警（不发起连接）。"""
    v = _ffi.take_json(_ffi.lib.gtls_check_profile(spec.encode()))
    if v is None:
        _check_error()
    return v


class CaseInsensitiveDict(MutableMapping):
    """大小写不敏感的 headers 容器（语义对齐 requests.structures.CaseInsensitiveDict）。

    保留插入时的原始大小写用于回传，查找/删除一律按小写键。
    """

    def __init__(self, data=None, **kwargs):
        self._store: dict[str, tuple[str, str]] = {}
        if data is None:
            data = {}
        self.update(data, **kwargs)

    def __setitem__(self, key, value):
        self._store[key.lower()] = (key, value)

    def __getitem__(self, key):
        return self._store[key.lower()][1]

    def __delitem__(self, key):
        del self._store[key.lower()]

    def __iter__(self):
        return (orig for orig, _ in self._store.values())

    def __len__(self):
        return len(self._store)

    def lower_items(self):
        """按小写键迭代（用于比较）。"""
        return ((low, v[1]) for low, v in self._store.items())

    def __eq__(self, other):
        if isinstance(other, Mapping):
            other = CaseInsensitiveDict(other)
        else:
            return NotImplemented
        return dict(self.lower_items()) == dict(other.lower_items())

    def copy(self):
        return CaseInsensitiveDict(self._store.values())

    def __repr__(self):
        return str(dict(self.items()))


def parse_charset(content_type: str):
    """从 Content-Type 提取 charset；没有则返回 None（对齐 requests 的 encoding 语义）。"""
    if not content_type:
        return None
    for part in content_type.split(";")[1:]:
        k, _, v = part.strip().partition("=")
        if k.strip().lower() == "charset":
            return v.strip().strip('"').strip("'") or None
    return None


class Response:
    """响应：头部在构造时可用，body 按需读取并缓存。

    常用属性/方法（对齐 requests）：``status_code`` ``ok`` ``headers`` ``reason``
    ``url`` ``method`` ``elapsed`` ``encoding`` ``content`` ``text`` ``json()``
    ``iter_content()`` ``iter_lines()`` ``raise_for_status()`` ``close()``。

    geektls 专有：``used_protocol``（协商到的协议，h2/h3/http/1.1）、``selfcheck``
    （本次握手的 JA3/JA4 自算与期望值比对）。

    ``cookies`` 是本响应里 ``Set-Cookie`` 的解析结果（requests 同名）；想让它参与
    后续请求就 ``session.cookies.update(r.cookies)``（引擎自己的 jar 本来就已自动
    收下它们，这里给的是显式可读/可改的那一份）。
    """

    def __init__(self, handle: int, *, method: str = None, url: str = None, elapsed: float = None):
        self._handle = handle
        info = _ffi.take_json(_ffi.lib.gtls_response_info(handle))
        if info is None:
            _check_error()

        self.status_code = int(info.get("status", 0))
        self.status = self.status_code  # 兼容 0.1.0 起的旧名
        self.raw_headers = [(k, v) for k, v in info.get("headers", [])]
        self.headers = CaseInsensitiveDict(self.raw_headers)
        self.used_protocol = info.get("used_protocol", "")
        self.http_version = self.used_protocol
        self.selfcheck = info.get("selfcheck", {}) or {}
        # T-DECOMP：线上 Content-Encoding 原值 / 是否已透明解压 / 告警
        self.content_encoding = info.get("content_encoding", "")
        self.decoded = bool(info.get("decoded", False))
        self.warnings = info.get("warnings") or []
        # 本响应的 Set-Cookie（requests 同名）；要让它们参与后续请求就
        # session.cookies.update(r.cookies)（引擎 jar 本来就已自动收下）。
        self.cookies = _parse_set_cookie(self.raw_headers)

        self.method = method
        self.url = url
        self.elapsed = elapsed
        self.reason = _REASON.get(self.status_code, "")
        # Content-Type 里声明的编码；没有声明则为 None（文本读取时再探测）。
        self.encoding = parse_charset(self.headers.get("content-type", ""))

        self._content = None
        self._json = None
        self._closed = False

    # ---- 状态 ----

    @property
    def ok(self) -> bool:
        """4xx/5xx 之外为 True（requests 语义）。"""
        return self.status_code < 400

    def __bool__(self) -> bool:
        return self.ok

    def raise_for_status(self) -> None:
        """>=400 时抛 HTTPError（GeekTLSError 子类，异常上挂 .response）。"""
        if self.status_code >= 400:
            raise HTTPError(
                "%d %s" % (self.status_code, self.reason or "HTTP error"),
                response=self,
            )

    # ---- 读取 ----

    def iter_content(self, chunk_size: int = 65536, decode_unicode: bool = False):
        """流式读 body（requests 同名方法）。

        decode_unicode=True 时按响应编码增量解码为 str（跨块多字节字符不会切坏）。
        """
        decoder = None
        if decode_unicode:
            enc = self.encoding or "utf-8"
            try:
                decoder = codecs.getincrementaldecoder(enc)()
            except LookupError:
                decoder = codecs.getincrementaldecoder("utf-8")()
        buf = _ffi.ctypes.create_string_buffer(chunk_size)
        while True:
            n = _ffi.lib.gtls_response_read(self._handle, buf, chunk_size)
            if n < 0:
                _check_error()
            if n == 0:
                break
            chunk = buf.raw[:n]
            yield decoder.decode(chunk) if decoder is not None else chunk
        if decoder is not None:
            tail = decoder.decode(b"", final=True)
            if tail:
                yield tail

    # 旧名（0.1.x 早期示例用过），保留兼容。
    def iter_bytes(self, chunk_size: int = 65536):
        """流式读 body（等同 iter_content 的旧名）。"""
        return self.iter_content(chunk_size)

    def iter_lines(self, chunk_size: int = 65536, decode_unicode: bool = False):
        """按行流式（以 \\n 切分，跨块拼接；保留行尾换行符）。"""
        pending = b""
        for chunk in self.iter_content(chunk_size):
            if isinstance(chunk, str):
                chunk = chunk.encode(self.encoding or "utf-8", "replace")
            pending += chunk
            while True:
                idx = pending.find(b"\n")
                if idx < 0:
                    break
                line = pending[: idx + 1]
                pending = pending[idx + 1 :]
                yield line.decode(self.encoding or "utf-8", "replace") if decode_unicode else line
        if pending:
            yield pending.decode(self.encoding or "utf-8", "replace") if decode_unicode else pending

    @property
    def content(self) -> bytes:
        """整个 body（首次访问读完并缓存）。"""
        if self._content is None:
            self._content = b"".join(self.iter_content(65536))
        return self._content

    def read(self) -> bytes:
        """一次性读完 body（等同 .content 的旧名）。"""
        return self.content

    def bytes(self) -> bytes:
        """body 字节（等同 .content；与 Go 的 Bytes()、Node 的 bytes() 命名对齐）。"""
        return self.content

    def header(self, name: str, default=None):
        """大小写不敏感取单个响应头（与 Go 的 Header()、Node 的 header() 对齐）。"""
        return self.headers.get(name, default)

    def _text_encoding(self) -> str:
        if self.encoding:
            return self.encoding
        for enc in _FALLBACK_ENCODINGS:
            try:
                self.content.decode(enc)
                return enc
            except (UnicodeDecodeError, LookupError):
                continue
        return "latin-1"

    @property
    def apparent_encoding(self) -> str:
        """没声明 charset 时的探测结果（utf-8 → gb18030 → latin-1）。"""
        return self._text_encoding()

    @property
    def text(self) -> str:
        """按响应编码解码的文本（未声明 charset 时自动探测）。"""
        return self.content.decode(self._text_encoding(), errors="replace")

    def json(self, **kwargs):
        """解析 JSON（按 charset 解码，兼容 BOM；结果缓存）。"""
        if self._json is None:
            data = self.content
            enc = self.encoding or "utf-8"
            try:
                text = data.decode(enc)
            except (UnicodeDecodeError, LookupError):
                text = data.decode("utf-8", errors="replace")
            if text.startswith("\ufeff"):
                text = text[1:]
            self._json = _json.loads(text, **kwargs)
        return self._json

    # ---- 生命周期 ----

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

    def __repr__(self):
        return "<Response [%d] %s>" % (self.status_code, self.used_protocol or "-")


class WebSocket:
    """wss:// WebSocket 连接（RFC 6455；握手走 geektls 指纹链路，Upgrade 头序受控）。

    拉模型（与 ABI 哲学一致，无回调）：``send()`` / ``recv(timeout)`` / ``close()``。
    opcode 常量：``OP_TEXT``/``OP_BINARY``/``OP_CLOSE``/``OP_PING``/``OP_PONG``。
    服务端 ping 会自动回 pong；收到对端 close 时 ``recv`` 返回 ``(OP_CLOSE, payload)``。
    ``compress=True`` 让握手 offer ``permessage-deflate``（RFC 7692）；只有服务端真的
    接受才启用，之后 ``send``/``recv`` 收发的仍是**明文**（RSV1 位由库管理）。
    """

    OP_TEXT = 1
    OP_BINARY = 2
    OP_CLOSE = 8
    OP_PING = 9
    OP_PONG = 10

    def __init__(self, session_handle: int, url: str, headers=None, timeout=None,
                 compress: bool = False):
        import ctypes as _ct
        self._ct = _ct
        payload = {"url": url}
        if headers:
            items = headers.items() if isinstance(headers, Mapping) else headers
            payload["headers"] = [[k, v] for k, v in items]
        if timeout is not None:
            payload["timeout_ms"] = int(float(timeout) * 1000)
        if compress:
            payload["compress"] = True
        self._handle = _ffi.lib.gtls_ws_connect(
            session_handle, _json.dumps(payload).encode())
        if not self._handle:
            _check_error()

    def send(self, data, opcode: int = None) -> None:
        """发送一帧。data 为 str 按 text 发（utf-8），bytes 按 binary；
        显式 opcode 优先（ping/pong/close 也可主动发）。"""
        if opcode is None:
            opcode = self.OP_TEXT if isinstance(data, str) else self.OP_BINARY
        if isinstance(data, str):
            data = data.encode()
        if _ffi.lib.gtls_ws_send(self._handle, opcode, bytes(data), len(data)) != 0:
            _check_error()

    def recv(self, timeout: float = None, buf_size: int = 1 << 20):
        """收一条完整消息 → (opcode, bytes)。timeout 秒（None=阻塞等）。"""
        buf = _ffi.ctypes.create_string_buffer(buf_size)
        opcode = _ffi.ctypes.c_int(0)
        n = _ffi.lib.gtls_ws_recv(self._handle, buf, buf_size,
                                  int(timeout * 1000) if timeout else 0,
                                  _ffi.ctypes.byref(opcode))
        if n < 0:
            _check_error()
        return opcode.value, buf.raw[:n]

    def recv_text(self, timeout: float = None) -> str:
        op, data = self.recv(timeout)
        if op == self.OP_CLOSE:
            raise GeekTLSError("ws_closed", "connection closed by peer")
        return data.decode("utf-8", "replace")

    def close(self, code: int = 1000) -> None:
        if self._handle:
            _ffi.lib.gtls_ws_close(self._handle, code)
            self._handle = 0

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass


# 请求级 payload 里允许透传的字段（引擎 Request 的 JSON 名）。绑定把 kwargs 直接
# 拼进 request_json，而引擎忽略未知字段 ⇒ 不在这里挡一道，"会话级选项写到了请求
# 上"就会变成静默失效（A5-1 同一口径）。
_REQUEST_LEVEL_FIELDS = {"stream", "force_http3", "auto_decompress"}

# 会话级选项的 JSON 名（= 引擎 SessionOptions 的字段，一个不多一个不少）。
_SESSION_LEVEL_FIELDS = {
    "proxy", "proxy_from_env", "timeout_ms", "read_timeout_ms", "redirect_max",
    "cookie_jar", "insecure_skip_verify", "auto_decompress", "ca_bundle",
    "client_cert", "client_key", "resolve", "local_address", "ip_version",
    "protocols", "h3",
    "header_order", "identity_sync",
}


def _pick_proxy(proxies, scheme: str = None) -> str:
    """从 requests 风格 proxies（dict 或 str）里取出**本次请求**要用的一个代理 URL。

    dict 时按目标 scheme 选（`{"http": …, "https": …}`），再退 `"all"`，最后退任意
    非空值。引擎一次只支持一个代理 URL，"分档"由本函数在每请求时选出来。
    """
    if isinstance(proxies, str):
        return proxies
    if isinstance(proxies, Mapping):
        keys = []
        if scheme:
            keys += [scheme, scheme + "://"]
        keys += ["all", "all://"]
        if not scheme:
            keys += ["https", "http", "https://", "http://"]
        for key in keys:
            if proxies.get(key):
                return proxies[key]
        for v in proxies.values():
            if v:
                return v
    raise ValueError("proxies 需要是形如 {'https': 'http://host:port'} 的字典或代理 URL 字符串")


def _scheme_proxies(proxies) -> bool:
    """proxies 是否按 scheme 分档（决定建会话时定死还是每请求选一次）。"""
    if not isinstance(proxies, Mapping):
        return False
    return any(k in proxies for k in ("http", "https", "http://", "https://"))


def _url_scheme(url: str) -> str:
    return url.split("://", 1)[0].lower() if "://" in url else ""


class Cookies(MutableMapping):
    """轻量 cookie jar（requests `RequestsCookieJar` 的可用子集）。

    只做 name → value 的会话级视图与常用方法（`get` / `set` / `update` / `clear` /
    `get_dict`）。**不做**域 / 路径 / 过期策略：线上 Set-Cookie 的存取与重发由引擎的
    jar 负责（它同时覆盖重定向中间跳），这里负责"用户显式声明的 cookie"与"把响应里
    看到的 Set-Cookie 汇总给你再喂回去"。
    """

    def __init__(self, data=None, **kwargs):
        self._c = {}
        if data:
            self.update(data)
        if kwargs:
            self.update(kwargs)

    @staticmethod
    def _value(value):
        # requests 允许 jar 里放带 .value 的 Cookie 对象
        return getattr(value, "value", value)

    def __getitem__(self, name):
        return self._c[name]

    def __setitem__(self, name, value):
        self._c[str(name)] = self._value(value)

    def __delitem__(self, name):
        del self._c[name]

    def __iter__(self):
        return iter(self._c)

    def __len__(self):
        return len(self._c)

    def __repr__(self):
        return "Cookies(%r)" % (self._c,)

    def set(self, name, value, domain="", path="/"):  # noqa: A003 - requests 同名
        """requests 同名方法（domain/path 只记录签名，不做匹配）。"""
        self._c[str(name)] = self._value(value)

    def get_dict(self, domain=None, path=None) -> dict:
        return dict(self._c)

    def update(self, other=None, **kwargs):  # type: ignore[override]
        if other is None:
            other = {}
        if isinstance(other, Mapping):
            items = list(other.items())
        elif isinstance(other, Cookies):
            items = list(other.items())
        else:
            items = []
            for item in other:
                if hasattr(item, "name") and hasattr(item, "value"):
                    items.append((item.name, item.value))
                elif isinstance(item, (list, tuple)) and len(item) == 2:
                    items.append((item[0], item[1]))
        for k, v in items:
            self._c[str(k)] = self._value(v)
        for k, v in kwargs.items():
            self._c[str(k)] = self._value(v)

    def copy(self) -> "Cookies":
        return Cookies(self._c)

    def clear(self) -> None:
        self._c.clear()

    def get_cookie_header(self, base: str = "") -> str:
        """渲染成 `Cookie:` 头的值；``base`` 是已存在的头，**同名以 base 为准**
        （requests/http.cookiejar 同语义：显式写下的 cookie 不会被 jar 覆盖）。"""
        return _render_cookie_header(base, self)


def _render_cookie_header(*layers) -> str:
    """按"先到先得"合并多层 cookie（每层是 ``Cookies`` 或 ``"a=1; b=2"`` 字符串）。

    调用点按优先级从高到低传：显式 ``Cookie`` 头 → 请求级 ``cookies=`` →
    ``Session.cookies``（同名以先出现的那层为准）。
    """
    parts, seen = [], set()
    for layer in layers:
        if not layer:
            continue
        if isinstance(layer, Cookies):
            items = list(layer.items())
        else:
            items = []
            for pair in str(layer).split(";"):
                name, _, val = pair.strip().partition("=")
                if name:
                    items.append((name, val))
        for k, v in items:
            if k not in seen:
                seen.add(k)
                parts.append("%s=%s" % (k, v))
    return "; ".join(parts)


def _cookies_from(value) -> "Cookies":
    """把 dict / list[pair] / `"a=1; b=2"` / Cookies / cookiejar 归一成 Cookies。"""
    if isinstance(value, Cookies):
        return value
    if isinstance(value, str):
        pairs = []
        for part in value.split(";"):
            name, _, val = part.strip().partition("=")
            if name:
                pairs.append((name, val))
        return Cookies(pairs)
    if isinstance(value, Mapping):
        return Cookies(value)
    if hasattr(value, "__iter__"):
        jar = Cookies()
        jar.update(value)
        return jar
    raise ValueError("cookies 需要是 dict / list[tuple] / 'a=1; b=2' 字符串 / Cookies")


def _parse_set_cookie(headers) -> "Cookies":
    """从响应头里解析 Set-Cookie（只取 name=value，属性忽略）。"""
    jar = Cookies()
    for k, v in headers:
        if k.lower() != "set-cookie":
            continue
        name, _, val = v.split(";", 1)[0].partition("=")
        if name.strip():
            jar[name.strip()] = val.strip()
    return jar


def _with_params(url: str, params) -> str:
    """把 params（dict/list of pairs/str）拼到 URL 上。"""
    if not params:
        return url
    if isinstance(params, str):
        query = params.lstrip("?")
    else:
        query = urlencode(params, doseq=True)
    if not query:
        return url
    return url + ("&" if "?" in url else "?") + query


def _pem_or_path(value, field):
    """把 verify/cert 的取值归一成字符串（内联 PEM / 文件路径 / 目录）。

    引擎自己按内容判断是 PEM 文本还是路径，这里只做类型收敛。``None`` 返回
    ``None``（= 用默认）；非文本类型或空串直接报错——配了 CA / 证书却被静默
    丢掉，等于悄悄把证书校验退回系统根，不可接受。
    """
    if value is None:
        return None
    if hasattr(value, "__fspath__"):
        value = os.fspath(value)
    if isinstance(value, bytes):
        try:
            value = value.decode()
        except UnicodeDecodeError:
            raise ValueError("%s 不是合法的 PEM / 路径文本" % field) from None
    if not isinstance(value, str) or not value.strip():
        raise ValueError("%s 需要是路径（含 .pem 的目录也可以）或 PEM 文本" % field)
    return value


def _timeout_ms(value, field):
    """秒 → 毫秒（None = 不限，原样返回 None）。"""
    if value is None:
        return None
    try:
        return int(float(value) * 1000)
    except (TypeError, ValueError):
        raise ValueError("%s 需要是秒数（int/float）或 None" % field) from None


def _apply_timeout(opts: dict, timeout, read_timeout) -> None:
    """requests 风格 timeout → 引擎的两段超时。

    ``timeout=5``：到响应头为止的上限（``timeout_ms``）。
    ``timeout=(connect, read)``：connect 进 ``timeout_ms``，read 进
    ``read_timeout_ms``（元组里任一项可以是 None = 不限）。
    ``read_timeout`` 单独给 body 读取空闲上限（覆盖元组里的 read 值）。
    """
    if isinstance(timeout, (tuple, list)):
        if len(timeout) != 2:
            raise ValueError("timeout 元组需要是 (connect, read) 两项")
        connect, read = timeout
        if connect is not None:
            opts["timeout_ms"] = _timeout_ms(connect, "timeout[0]")
        if read is not None:
            opts["read_timeout_ms"] = _timeout_ms(read, "timeout[1]")
    elif timeout is not None:
        opts["timeout_ms"] = _timeout_ms(timeout, "timeout")
    if read_timeout is not None:
        opts["read_timeout_ms"] = _timeout_ms(read_timeout, "read_timeout")


def _auth_header(auth) -> str:
    """requests 风格 auth → `Authorization` 头的值（只支持 HTTP Basic）。"""
    if auth is None:
        return None
    if isinstance(auth, (tuple, list)) and len(auth) == 2:
        user, password = auth
    elif hasattr(auth, "username") and hasattr(auth, "password"):
        user, password = auth.username, auth.password
    elif hasattr(auth, "user") and hasattr(auth, "password"):
        user, password = auth.user, auth.password
    else:
        raise ValueError(
            "auth 只支持 (user, password) 或带 username/user + password 属性的对象（HTTP Basic）"
        )
    raw = ("%s:%s" % (user, password)).encode()
    return "Basic " + base64.b64encode(raw).decode()


def _apply_auth(hdrs: "CaseInsensitiveDict", auth) -> None:
    """把 auth 落到 Authorization 头；显式给了该头就以调用方的为准。"""
    header = _auth_header(auth)
    if header is None:
        return
    if "authorization" in hdrs:
        return
    hdrs["authorization"] = header


def _apply_verify(opts: dict, verify) -> None:
    """requests 风格 verify → 会话选项。

    True/None 用系统信任库；False 跳过校验；路径（目录也可以）或 PEM 文本
    作为**自持信任库**（替换系统根，与 requests 语义一致）。
    """
    if verify is None or verify is True:
        return
    if verify is False:
        opts["insecure_skip_verify"] = True
        return
    opts["ca_bundle"] = _pem_or_path(verify, "verify")


def _apply_cert(opts: dict, cert, cert_key) -> None:
    """requests 风格 cert → 会话选项（mTLS 客户端证书）。

    接受：路径或 PEM 文本（证书+私钥可同文件）、``(证书, 私钥)`` 二元组、
    ``(证书, 私钥, password)`` 三元组（password 必须为 None：不支持加密私钥）。
    ``cert_key`` 关键字可单独提供私钥（覆盖二元组里的第二项）。
    """
    if cert is None:
        if cert_key is None:
            return
        # 只给私钥：仍然写进会话选项，由引擎报"client_key 需要与 client_cert
        # 同时提供"，免得私钥路径被静默丢弃（错误消息只在引擎维护一份）。
        opts["client_key"] = _pem_or_path(cert_key, "cert_key")
        return
    if isinstance(cert, (str, bytes)) or hasattr(cert, "__fspath__"):
        client, key = _pem_or_path(cert, "cert"), None
    elif isinstance(cert, (tuple, list)):
        if len(cert) == 3 and cert[2] is not None:
            raise ValueError("不支持加密私钥（cert 三元组的 password 需为 None）")
        if len(cert) not in (1, 2):
            raise ValueError("cert 元组需要是 (证书,) 或 (证书, 私钥)")
        client = _pem_or_path(cert[0], "cert[0]")
        key = _pem_or_path(cert[1], "cert[1]") if len(cert) > 1 else None
    else:
        raise ValueError(
            "cert 只接受路径 / PEM 文本 / (证书, 私钥) 元组，收到 %s"
            % (type(cert).__name__,)
        )
    opts["client_cert"] = client
    if cert_key is not None:
        key = _pem_or_path(cert_key, "cert_key")
    if key is not None:
        opts["client_key"] = key


class Session:
    """指纹伪造会话（requests 风格）。

        Session(impersonate="chrome_150")             # 或 profile={...} / ja3=… / ja4r=… / clienthello_hex=…
        Session(impersonate="chrome_150", proxies={"https": "http://127.0.0.1:8080"},
                timeout=10, verify=False, allow_redirects=False)
        Session(impersonate="chrome_150", verify="/etc/ssl/certs/internal-ca.pem")   # 自持信任库
        Session(impersonate="chrome_150", cert=("client.crt", "client.key"))         # mTLS

    参数：``headers`` 会话默认请求头；``proxies``/``timeout``/``read_timeout``/
    ``verify``/``cert``/``allow_redirects``/``max_redirects``/``cookies``/``auth``
    为 requests 风格别名（映射到引擎的 proxy/timeout_ms/read_timeout_ms/
    insecure_skip_verify/redirect_max/cookie_jar；``auth`` 是绑定层的 Basic 头条）。
    ``proxies`` 是 dict 且含 http/https 分档时按目标 scheme **每请求**选一个；
    ``cookies`` 给 dict/list/字符串/``Cookies`` 时成为会话级 jar（每请求渲染成
    Cookie 头），给 bool 时只开关引擎 jar。
    ``timeout`` 覆盖"dial+TLS+响应头"；``read_timeout`` 是**每次读 body** 的空闲
    上限（慢速/挂死的 body 会抛错并作废该连接，0/None = 不限）。
    ``verify``：True（默认，系统信任库）/ False（跳过校验）/ 路径或 PEM 文本
    （自持 CA bundle，**替换**系统根，与 requests 一致）；
    ``cert``：str 路径或 PEM（证书+私钥可同文件）、(证书, 私钥) 二元组，
    ``cert_key`` 可单独给私钥。
    ``trust_env``（requests 同名）：False = 不读 ``HTTPS_PROXY`` / ``ALL_PROXY``，
    只认显式的 ``proxies``/``proxy``；默认 True 会读，并按 ``NO_PROXY`` 豁免
    （映射到引擎的 ``proxy_from_env``）。
    ``resolve``（curl ``--resolve``）：``{"host[:port]": "IP"}``，把域名钉到固定地址。
    只改"连到哪"——SNI / Host / 指纹字节仍是 URL 里的原域名。键不做通配。
    ``local_address``（httpx 同名）：出网源 IP（网卡名不支持）；代理场景绑的是到
    代理那一条。``ip_version``：``"4"`` / ``"6"``（curl -4/-6）。
    ``resolve`` 与 ``ip_version`` 只在本地解析的档位生效（直连 / socks5 / socks4）；
    socks5h / socks4a / CONNECT 由代理解析，这两项不参与。
    其余未知关键字原样透传给引擎会话选项。
    """

    def __init__(self, impersonate: str = None, *, profile=None,
                 ja3: str = None, ja4: str = None, ja4r: str = None,
                 clienthello_hex: str = None,
                 headers=None, proxies=None, timeout=None, read_timeout=None,
                 verify=None,
                 cert=None, cert_key=None,
                 allow_redirects=None, max_redirects=None, cookies=None,
                 auth=None, trust_env=None,
                 resolve=None, local_address=None, ip_version=None,
                 protocols=None, h3=None, header_order=None, identity_sync=None,
                 **options):
        config = {}
        if isinstance(profile, str):
            # 允许直接传 profile JSON 文本（省得调用方自己 json.loads）。
            profile = _json.loads(profile)
        for key, val in (("impersonate", impersonate), ("profile", profile),
                         ("ja3", ja3), ("ja4", ja4), ("ja4r", ja4r),
                         ("clienthello_hex", clienthello_hex)):
            if val is not None:
                config[key] = val

        opts = {k: v for k, v in options.items() if v is not None}
        # proxies：dict 且含 scheme 分档时不在建会话时定死，改成每请求按目标
        # scheme 选（requests 语义）；单值 / 只有 "all" 的照旧落到会话级。
        self._proxies = None
        if proxies is not None:
            if _scheme_proxies(proxies):
                self._proxies = dict(proxies)
            else:
                opts["proxy"] = _pick_proxy(proxies)
        if trust_env is not None:
            opts["proxy_from_env"] = bool(trust_env)
        if resolve is not None:
            if not isinstance(resolve, dict):
                raise ValueError('resolve 需要 {"host[:port]": "IP"} 形态的 dict')
            opts["resolve"] = {str(k): str(v) for k, v in resolve.items()}
        if local_address is not None:
            opts["local_address"] = str(local_address)
        if ip_version is not None:
            opts["ip_version"] = str(ip_version)
        # 协议选择（G8）：默认 h1.1 + h2（**不含 H3**，与 curl_cffi 同口径）。
        #   protocols=["h1.1"] / ["h2"] / ["h2","h3"] / ["h3"]（只给 h3 = 会话级强制）
        #   h3=True 是便捷写法（= 默认集合加 h3）；两者同时给会被引擎拒（不静默取其一）。
        if protocols is not None:
            if isinstance(protocols, str):
                protocols = [protocols]
            opts["protocols"] = [str(p).strip() for p in protocols if str(p).strip()]
        if h3 is not None:
            opts["h3"] = bool(h3)
        # 头序与身份自洽（G9）：
        #   header_order="preserve"（默认）/ "input"（按你给的顺序）/ "random"（打乱）
        #   identity_sync="auto"（默认：UA 与预设身份冲突时校正 sec-ch-ua* 并告警）/ "off"
        if header_order is not None:
            opts["header_order"] = str(header_order)
        if identity_sync is not None:
            opts["identity_sync"] = str(identity_sync)
        _apply_timeout(opts, timeout, read_timeout)
        _apply_verify(opts, verify)
        _apply_cert(opts, cert, cert_key)
        if allow_redirects is False:
            opts["redirect_max"] = -1
        if max_redirects is not None:
            opts["redirect_max"] = int(max_redirects)
        # cookies：bool 只开关引擎 jar；其余（dict / list / str / Cookies）成为会话级
        # jar —— 每请求渲染成显式 Cookie 头，响应里的 Set-Cookie 自动并入。
        self.cookies = Cookies()
        if cookies is not None:
            if isinstance(cookies, bool):
                opts["cookie_jar"] = cookies
            else:
                self.cookies.update(_cookies_from(cookies))
        if auth is not None:
            _auth_header(auth)  # 形态错在建会话时就报，不留到第一跳
        self.auth = auth

        # 引擎的会话选项解码忽略未知字段 ⇒ 拼错的键（`local_addr`、`resolveAll`）
        # 会静默失效，而这几项决定"连接到底走哪条路"。在绑定层拦下来。
        unknown = sorted(set(opts) - _SESSION_LEVEL_FIELDS)
        if unknown:
            raise ValueError(
                "会话不接受这些选项 %s；可用的是 %s（requests 风格别名 proxies/timeout/"
                "verify/cert/cookies/trust_env 会自动映射）"
                % (", ".join(unknown), ", ".join(sorted(_SESSION_LEVEL_FIELDS)))
            )

        self.headers = CaseInsensitiveDict(headers or {})

        self._client = _ffi.lib.gtls_client_new(_json.dumps(config).encode())
        if not self._client:
            _check_error()
        self._session = 0
        try:
            self._session = _ffi.lib.gtls_session_new(
                self._client, _json.dumps(opts).encode())
            if not self._session:
                _check_error()
        except BaseException:
            _ffi.lib.gtls_client_close(self._client)
            self._client = 0
            raise

    def request(self, method: str, url: str, *, params=None, data=None, json=None,
                headers=None, body=None, timeout=None, timeout_ms: int = None,
                read_timeout=None, read_timeout_ms: int = None,
                proxy: str = None, proxies=None, verify=None, cert=None, cert_key=None,
                allow_redirects=None, max_redirects=None, auth=None, cookies=None,
                **kwargs) -> Response:
        """发请求；响应头到达即返回（body 按需读取：见 Response）。

        - ``params`` 拼查询串；``data``（dict / list[tuple] → 表单编码；str/bytes →
          原样；其它可迭代 → chunked 流式上传）、``json`` 生成 body；
        - ``headers`` 覆盖/追加会话默认头；``cookies``（dict/list/str/Cookies）本次请求
          的 cookie（与 ``Session.cookies`` 合并，请求级同名优先）；
        - ``auth=(user, password)`` HTTP Basic；自己给了 Authorization 头以你的为准；
        - ``timeout`` 秒或 ``(connect, read)`` 元组 或 ``timeout_ms`` 毫秒，覆盖会话默认；
        - ``read_timeout`` 秒 或 ``read_timeout_ms`` 毫秒：单次 body 读取的空闲上限，
          超时抛 ``geektls.Timeout``（GeekTLSError 子类，``code="read_timeout"``）并作废该连接；
        - ``allow_redirects`` / ``max_redirects`` / ``proxies`` 请求级覆盖会话级；
        - ``verify`` / ``cert`` 是会话级，传到这里会报错（避免静默失效）。
        - 其余关键字只接受请求级字段 ``stream`` / ``force_http3`` / ``auto_decompress``；
          再多的键会报错——引擎忽略未知字段，静默失效比报错更难查。
        """
        if verify is not None or cert is not None or cert_key is not None:
            raise ValueError(
                "verify / cert 是会话级设置：请在 Session(...) 里传；请求级可用的是 "
                "timeout_ms / read_timeout_ms / proxy(s) / cookies / auth / "
                "allow_redirects / max_redirects / stream / force_http3"
            )
        unknown = sorted(set(kwargs) - _REQUEST_LEVEL_FIELDS)
        if unknown:
            raise ValueError(
                "请求不接受这些字段 %s：请求级可用字段只有 timeout_ms / read_timeout_ms / "
                "proxy / stream / force_http3 / auto_decompress；会话级设置"
                "（resolve / local_address / ip_version / trust_env / verify / cert …）"
                "请在 Session(...) 里传" % ", ".join(unknown)
            )

        if params:
            url = _with_params(url, params)

        hdrs = CaseInsensitiveDict(self.headers)
        if headers:
            hdrs.update(headers)
        _apply_auth(hdrs, self.auth if auth is None else auth)
        # Cookie：显式 Cookie 头 > 请求级 cookies= > 会话 jar，渲染成一个显式
        # Cookie 头；引擎自己的 jar 只补这里没有的名字（见 appendCookieHeader）。
        req_cookies = Cookies()
        if cookies is not None:
            req_cookies.update(_cookies_from(cookies))
        cookie_header = _render_cookie_header(hdrs.get("cookie"), req_cookies, self.cookies)
        if cookie_header:
            hdrs["cookie"] = cookie_header

        payload = {"method": method.upper(), "url": url}

        raw_body = None
        stream_chunks = None
        if json is not None:
            raw_body = _json.dumps(json, ensure_ascii=False).encode()
            if "content-type" not in hdrs:
                hdrs["content-type"] = "application/json"
        elif data is not None:
            if isinstance(data, Mapping):
                raw_body = urlencode(data, doseq=True).encode()
                if "content-type" not in hdrs:
                    hdrs["content-type"] = "application/x-www-form-urlencoded"
            elif isinstance(data, (list, tuple)) and data and all(
                    isinstance(x, (list, tuple)) and len(x) == 2 for x in data):
                # requests 语义：list[tuple] 是**表单**（同名键重复展开），不是流式
                # body —— 这条以前会被当成可迭代 body 走 chunked，等于换个方法发错东西。
                raw_body = urlencode(data, doseq=True).encode()
                if "content-type" not in hdrs:
                    hdrs["content-type"] = "application/x-www-form-urlencoded"
            elif isinstance(data, str):
                raw_body = data.encode()
            elif isinstance(data, (bytes, bytearray, memoryview)):
                raw_body = bytes(data)
            else:
                stream_chunks = data  # 可迭代 → chunked 流式上传
        elif body is not None:  # 0.1.x 早期参数名，保留兼容
            if isinstance(body, str):
                raw_body = body.encode()
            elif isinstance(body, (bytes, bytearray, memoryview)):
                raw_body = bytes(body)
            else:
                stream_chunks = body  # 迭代器/生成器 → chunked 流式上传

        if raw_body is not None:
            payload["body_b64"] = base64.b64encode(raw_body).decode()
        if len(hdrs):
            payload["headers"] = [[k, v] for k, v in hdrs.items()]
        _apply_timeout(payload, timeout, read_timeout)
        if timeout_ms is not None:
            payload["timeout_ms"] = timeout_ms
        if read_timeout_ms is not None:
            payload["read_timeout_ms"] = read_timeout_ms
        if proxies is not None:
            proxy = _pick_proxy(proxies, _url_scheme(url))
        if proxy is None and self._proxies:
            proxy = _pick_proxy(self._proxies, _url_scheme(url))
        if proxy:
            payload["proxy"] = proxy
        if allow_redirects is not None and allow_redirects is not True:
            if allow_redirects is not False:
                raise ValueError("allow_redirects 只接受 True / False")
            payload["redirect_max"] = -1
        if max_redirects is not None:
            payload["redirect_max"] = int(max_redirects)
        payload.update(kwargs)

        started = time.monotonic()
        if stream_chunks is not None:
            resp = self._stream_upload(payload, stream_chunks,
                                       method=payload["method"], url=url, started=started)
        else:
            handle = _ffi.lib.gtls_request(self._session, _json.dumps(payload).encode())
            if not handle:
                _check_error()
            resp = Response(handle, method=payload["method"], url=url,
                            elapsed=time.monotonic() - started)
        # 响应里的 Set-Cookie 并入会话 jar（与引擎 jar 的自动收发不冲突：
        # 同名以显式 Cookie 头为准，引擎只补缺）。
        self.cookies.update(resp.cookies)
        return resp

    def _stream_upload(self, payload: dict, chunks, *, method: str, url: str,
                       started: float) -> Response:
        """迭代器 body 的 chunked 流式上传（H1 线上 chunked 编码 / H2 DATA 帧流）。

        body 逐块经 gtls_request_write 发出，流尽后 finish 收响应头。
        中途出错时仍调 finish 回收 handle（finish 本身的错误忽略）。
        """
        up = _ffi.lib.gtls_request_begin(self._session, _json.dumps(payload).encode())
        if not up:
            _check_error()
        try:
            for chunk in chunks:
                if isinstance(chunk, str):
                    chunk = chunk.encode()
                else:
                    chunk = bytes(chunk)
                if not chunk:
                    continue
                if _ffi.lib.gtls_request_write(up, chunk, len(chunk)) < 0:
                    _check_error()
        except BaseException:
            try:
                _ffi.lib.gtls_request_finish(up)
            except Exception:
                pass
            raise
        resp = _ffi.lib.gtls_request_finish(up)
        if not resp:
            _check_error()
        return Response(resp, method=method, url=url,
                        elapsed=time.monotonic() - started)

    def get(self, url: str, **kwargs) -> Response:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs) -> Response:
        return self.request("POST", url, **kwargs)

    def put(self, url: str, **kwargs) -> Response:
        return self.request("PUT", url, **kwargs)

    def patch(self, url: str, **kwargs) -> Response:
        return self.request("PATCH", url, **kwargs)

    def delete(self, url: str, **kwargs) -> Response:
        return self.request("DELETE", url, **kwargs)

    def head(self, url: str, **kwargs) -> Response:
        return self.request("HEAD", url, **kwargs)

    def options(self, url: str, **kwargs) -> Response:
        return self.request("OPTIONS", url, **kwargs)

    def websocket(self, url: str, headers=None, timeout=None,
                  compress: bool = False) -> "WebSocket":
        """建立 wss:// WebSocket 连接（握手走本会话的指纹链路）。

        compress=True 时握手带 ``sec-websocket-extensions: permessage-deflate``；
        要精确控制 offer 参数就直接写在 headers 里（此时不必再传 compress）。
        """
        return WebSocket(self._session, url, headers=headers, timeout=timeout,
                         compress=compress)

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


# ---------------------------------------------------------------------------
# 模块级快捷 API（对齐 requests / curl_cffi.requests 的顶层用法）。
#
# 底层是**进程级共享默认会话**（懒创建、线程安全）：连接池与 cookie_jar 跟随它，
# 语义与 requests 的模块级 API 一致。首次 default_session(...) 可以传 Session(...)
# 的参数把默认会话配好（impersonate / verify / proxies / timeout…），之后只读；
# 需要不同指纹或隔离 cookie 时，请用独立的 ``with Session(...) as s:``。
# ---------------------------------------------------------------------------
_default_session: "Session | None" = None
_default_session_lock = threading.Lock()


def default_session(**options) -> "Session":
    """返回模块级共享会话；首次调用可传 ``Session(...)`` 的参数来配置它。

    会话已存在时再传 options 会报错（共享会话的指纹 / verify / 代理只在
    创建时定一次，避免"改了一半"的隐性状态）。
    """
    global _default_session
    with _default_session_lock:
        if _default_session is None:
            _default_session = Session(**options)
        elif options:
            raise ValueError(
                "默认会话已创建：配置只能在首次 default_session() 调用时给定"
            )
        return _default_session


def request(method: str, url: str, **kwargs) -> "Response":
    return default_session().request(method, url, **kwargs)


def get(url: str, **kwargs) -> "Response":
    return default_session().get(url, **kwargs)


def head(url: str, **kwargs) -> "Response":
    return default_session().head(url, **kwargs)


def post(url: str, **kwargs) -> "Response":
    return default_session().post(url, **kwargs)


def put(url: str, **kwargs) -> "Response":
    return default_session().put(url, **kwargs)


def patch(url: str, **kwargs) -> "Response":
    return default_session().patch(url, **kwargs)


def delete(url: str, **kwargs) -> "Response":
    return default_session().delete(url, **kwargs)


def options(url: str, **kwargs) -> "Response":
    return default_session().options(url, **kwargs)
