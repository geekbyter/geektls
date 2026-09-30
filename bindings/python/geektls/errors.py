"""geektls 异常类型。"""


class GeekTLSError(Exception):
    """core 通过 gtls_last_error 上报的结构化错误（{"code","message"}）。"""

    def __init__(self, code: str, message: str):
        super().__init__("[%s] %s" % (code, message))
        self.code = code
        self.message = message


class HTTPError(GeekTLSError):
    """`raise_for_status()` 抛出的异常（requests 同名；异常上挂 ``.response``）。

    继承 GeekTLSError ⇒ 既有的 ``except GeekTLSError`` 照旧能捕获。
    """

    def __init__(self, message: str, response=None):
        super().__init__("http_error", message)
        self.response = response


class Timeout(GeekTLSError):
    """读超时（``code="read_timeout"``）的专用类型，便于 ``except geektls.Timeout``。

    引擎仍以 ``read_timeout`` 码上报，这里只是在绑定层做类型细化：
    :func:`geektls.Timeout.from_error` 在码匹配时把 GeekTLSError 转成它。
    """

    def __init__(self, message: str):
        super().__init__("read_timeout", message)

    @classmethod
    def from_error(cls, err: "GeekTLSError"):
        """码是 read_timeout 就换成 Timeout，否则原样返回。"""
        if isinstance(err, GeekTLSError) and err.code == "read_timeout":
            return cls(err.message)
        return err
