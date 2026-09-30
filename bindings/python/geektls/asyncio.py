"""geektls 的 asyncio API（异步包装层）。

**诚实标注**：这是**线程池异步**，不是原生异步——内部用 ``asyncio.to_thread``
把同步 FFI 调用丢进默认 executor。语义与同步 API 完全一致（同样的指纹、
同样的 selfcheck），事件循环不被阻塞；但吞吐上限受 executor 线程数约束，
高并发压测请直接用多线程 + 同步 ``Session``（见 docs/benchmarks.md，
线程模型在 ctypes 阻塞期间释放 GIL，反而更高）。

用法与同步版镜像::

    import asyncio
    from geektls.asyncio import AsyncSession

    async def main():
        async with AsyncSession(impersonate="chrome_150") as s:
            r = await s.get("https://example.com")
            print(r.status_code)
            async for chunk in r.iter_bytes():
                ...

    asyncio.run(main())
"""

from __future__ import annotations

import asyncio

from . import Session, Response, WebSocket, GeekTLSError

__all__ = ["AsyncSession", "AsyncResponse", "AsyncWebSocket", "GeekTLSError"]

_SENTINEL = object()


class AsyncResponse:
    """同步 Response 的异步视图：属性直通，读 body 走 to_thread。"""

    def __init__(self, r: Response):
        self._r = r
        # 元信息在构造时就绪（同步 Response 已拿过头）
        self.status_code = r.status_code
        self.status = r.status
        self.ok = r.ok
        self.headers = r.headers
        self.raw_headers = r.raw_headers
        self.used_protocol = r.used_protocol
        self.selfcheck = r.selfcheck
        self.content_encoding = r.content_encoding
        self.decoded = r.decoded
        self.warnings = r.warnings
        self.url = r.url
        self.method = r.method
        self.reason = r.reason
        self.encoding = r.encoding
        # 与同步 Response 对齐的其余元信息（此前漏了这三项）
        self.cookies = r.cookies
        self.elapsed = r.elapsed
        self.http_version = r.http_version

    def header(self, name: str, default=None):
        """单个响应头（大小写不敏感；同步 Response 同名方法）。"""
        return self._r.header(name, default)

    async def read(self) -> bytes:
        return await asyncio.to_thread(self._r.read)

    async def bytes(self) -> bytes:
        return await self.read()

    async def content(self) -> bytes:  # noqa: D102 - 与同步 .content 对齐
        return await self.read()

    async def text(self) -> str:
        return await asyncio.to_thread(lambda: self._r.text)

    async def json(self, **kwargs):
        return await asyncio.to_thread(lambda: self._r.json(**kwargs))

    async def iter_bytes(self, chunk_size: int = 65536):
        """异步流式读 body（async generator 包同步迭代器）。"""
        it = self._r.iter_bytes(chunk_size)
        while True:
            chunk = await asyncio.to_thread(next, it, _SENTINEL)
            if chunk is _SENTINEL:
                break
            yield chunk

    async def iter_content(self, chunk_size: int = 65536, decode_unicode: bool = False):
        """同步 ``iter_content`` 的异步版（requests 同名参数）。"""
        it = self._r.iter_content(chunk_size, decode_unicode)
        while True:
            chunk = await asyncio.to_thread(next, it, _SENTINEL)
            if chunk is _SENTINEL:
                break
            yield chunk

    async def iter_lines(self, chunk_size: int = 65536, decode_unicode: bool = False):
        it = self._r.iter_lines(chunk_size, decode_unicode)
        while True:
            line = await asyncio.to_thread(next, it, _SENTINEL)
            if line is _SENTINEL:
                break
            yield line

    async def raise_for_status(self) -> None:
        self._r.raise_for_status()

    async def close(self) -> None:
        await asyncio.to_thread(self._r.close)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        await self.close()


class AsyncWebSocket:
    """同步 WebSocket 的异步视图（recv/send 走 to_thread）。"""

    def __init__(self, ws: WebSocket):
        self._ws = ws

    async def send(self, data, opcode: int = None) -> None:
        await asyncio.to_thread(self._ws.send, data, opcode)

    async def recv(self, timeout: float = None):
        return await asyncio.to_thread(self._ws.recv, timeout)

    async def recv_text(self, timeout: float = None) -> str:
        return await asyncio.to_thread(self._ws.recv_text, timeout)

    async def close(self, code: int = 1000) -> None:
        await asyncio.to_thread(self._ws.close, code)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        await self.close()


class AsyncSession:
    """异步会话：构造参数与 ``Session`` 完全一致。"""

    def __init__(self, *args, **kwargs):
        self._sync = Session(*args, **kwargs)

    async def request(self, method: str, url: str, **kwargs) -> AsyncResponse:
        r = await asyncio.to_thread(self._sync.request, method, url, **kwargs)
        return AsyncResponse(r)

    async def get(self, url: str, **kwargs) -> AsyncResponse:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs) -> AsyncResponse:
        return await self.request("POST", url, **kwargs)

    async def put(self, url: str, **kwargs) -> AsyncResponse:
        return await self.request("PUT", url, **kwargs)

    async def patch(self, url: str, **kwargs) -> AsyncResponse:
        return await self.request("PATCH", url, **kwargs)

    async def delete(self, url: str, **kwargs) -> AsyncResponse:
        return await self.request("DELETE", url, **kwargs)

    async def head(self, url: str, **kwargs) -> AsyncResponse:
        return await self.request("HEAD", url, **kwargs)

    async def options(self, url: str, **kwargs) -> AsyncResponse:
        return await self.request("OPTIONS", url, **kwargs)

    async def websocket(self, url: str, **kwargs) -> AsyncWebSocket:
        ws = await asyncio.to_thread(self._sync.websocket, url, **kwargs)
        return AsyncWebSocket(ws)

    async def close(self) -> None:
        await asyncio.to_thread(self._sync.close)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        await self.close()
