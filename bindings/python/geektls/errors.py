"""geektls 异常类型。"""


class GeekTLSError(Exception):
    """core 通过 gtls_last_error 上报的结构化错误（{"code","message"}）。"""

    def __init__(self, code: str, message: str):
        super().__init__("[%s] %s" % (code, message))
        self.code = code
        self.message = message
