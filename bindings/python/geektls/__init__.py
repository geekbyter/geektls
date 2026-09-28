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

- `verify` / `allow_redirects` 是**会话级**设置（引擎只在建会话时接受），
  要按请求切换请新建一个 Session；把它们传给 `request()` 会**明确报错**而不是静默忽略。
- `cookies` 只支持 bool（开关会话 cookie jar）；要带具体 Cookie 就往 `headers` 里塞
  `Cookie` 头。
- `reason` 由状态码在本地映射（RFC 9110 短语），不是服务端原文。
- `proxies` 只取其中一个代理（引擎一次只支持一个代理 URL）。
"""

from __future__ import annotations

import base64
import codecs
import json as _json
import time
from collections.abc import Mapping, MutableMapping
from urllib.parse import urlencode

from . import _ffi
from .errors import GeekTLSError

__all__ = [
    "Session",
    "Response",
    "CaseInsensitiveDict",
    "version",
    "init",
    "last_error",
    "list_presets",
    "describe_preset",
    "check_profile",
    "GeekTLSError",
    "__version__",
]

# 包版本与动态库版本是**两个**版本（见 docs/versioning.md）：包内库与包版本锁死，
# 运行时再用 version() 核对 ABI 主版本。
__version__ = "0.1.4"

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
        """>=400 时抛 GeekTLSError（异常上挂 .response）。"""
        if self.status_code >= 400:
            err = GeekTLSError(
                "http_error", "%d %s" % (self.status_code, self.reason or "HTTP error")
            )
            err.response = self
            raise err

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


def _pick_proxy(proxies) -> str:
    """从 requests 风格 proxies（dict 或 str）里取出一个代理 URL。"""
    if isinstance(proxies, str):
        return proxies
    if isinstance(proxies, Mapping):
        for key in ("https", "http", "all", "https://", "http://"):
            if proxies.get(key):
                return proxies[key]
        for v in proxies.values():
            if v:
                return v
    raise ValueError("proxies 需要是形如 {'https': 'http://host:port'} 的字典或代理 URL 字符串")


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


class Session:
    """指纹伪造会话（requests 风格）。

        Session(impersonate="chrome_150")             # 或 profile={...} / ja3=… / ja4r=… / clienthello_hex=…
        Session(impersonate="chrome_150", proxies={"https": "http://127.0.0.1:8080"},
                timeout=10, verify=False, allow_redirects=False)

    参数：``headers`` 会话默认请求头；``proxies``/``timeout``/``verify``/
    ``allow_redirects``/``cookies`` 为 requests 风格别名（映射到引擎的
    proxy/timeout_ms/insecure_skip_verify/redirect_max/cookie_jar）。
    其余未知关键字原样透传给引擎会话选项。
    """

    def __init__(self, impersonate: str = None, *, profile: dict = None,
                 ja3: str = None, ja4r: str = None, clienthello_hex: str = None,
                 headers=None, proxies=None, timeout=None, verify=None,
                 allow_redirects=None, cookies=None, **options):
        config = {}
        for key, val in (("impersonate", impersonate), ("profile", profile),
                         ("ja3", ja3), ("ja4r", ja4r),
                         ("clienthello_hex", clienthello_hex)):
            if val is not None:
                config[key] = val

        opts = {k: v for k, v in options.items() if v is not None}
        if proxies is not None:
            opts["proxy"] = _pick_proxy(proxies)
        if timeout is not None:
            opts["timeout_ms"] = int(float(timeout) * 1000)
        if verify is False:
            opts["insecure_skip_verify"] = True
        if allow_redirects is False:
            opts["redirect_max"] = -1
        if cookies is not None:
            if not isinstance(cookies, bool):
                raise ValueError(
                    "cookies 只支持 bool（会话级开关）；要带具体 Cookie 请放到 headers={'Cookie': '...'}"
                )
            opts["cookie_jar"] = cookies

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
                proxy: str = None, verify=None, allow_redirects=None, **kwargs) -> Response:
        """发请求；响应头到达即返回（body 按需读取：见 Response）。

        - ``params`` 拼查询串；``data``（dict→表单编码 / str/bytes→原样）、``json`` 生成 body；
        - ``headers`` 覆盖/追加会话默认头；
        - ``timeout`` 秒（float）或 ``timeout_ms`` 毫秒，覆盖会话默认；
        - ``verify`` / ``allow_redirects`` 是会话级，传到这里会报错（避免静默失效）。
        """
        if verify is not None or allow_redirects is not None:
            raise ValueError(
                "verify / allow_redirects 是会话级设置：请在 Session(...) 里传；"
                "请求级可用字段是 timeout_ms / proxy / stream / force_http3"
            )

        if params:
            url = _with_params(url, params)

        hdrs = CaseInsensitiveDict(self.headers)
        if headers:
            hdrs.update(headers)

        payload = {"method": method.upper(), "url": url}

        raw_body = None
        if json is not None:
            raw_body = _json.dumps(json, ensure_ascii=False).encode()
            if "content-type" not in hdrs:
                hdrs["content-type"] = "application/json"
        elif data is not None:
            if isinstance(data, Mapping):
                raw_body = urlencode(data, doseq=True).encode()
                if "content-type" not in hdrs:
                    hdrs["content-type"] = "application/x-www-form-urlencoded"
            elif isinstance(data, str):
                raw_body = data.encode()
            else:
                raw_body = bytes(data)
        elif body is not None:  # 0.1.x 早期参数名，保留兼容
            raw_body = body.encode() if isinstance(body, str) else bytes(body)

        if raw_body is not None:
            payload["body_b64"] = base64.b64encode(raw_body).decode()
        if len(hdrs):
            payload["headers"] = [[k, v] for k, v in hdrs.items()]
        if timeout is not None:
            payload["timeout_ms"] = int(float(timeout) * 1000)
        if timeout_ms is not None:
            payload["timeout_ms"] = timeout_ms
        if proxy:
            payload["proxy"] = proxy
        payload.update(kwargs)

        started = time.monotonic()
        resp = _ffi.lib.gtls_request(self._session, _json.dumps(payload).encode())
        if not resp:
            _check_error()
        return Response(resp, method=payload["method"], url=url,
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
