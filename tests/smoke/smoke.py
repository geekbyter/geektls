"""P0 冒烟：加载 c-shared 动态库，调 gtls_version，校验 abi==1。

库搜索顺序见 bindings/python/geektls/_ffi.py（GEEDTLS_LIB 环境变量优先）。
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "bindings", "python"))

from geektls import version  # noqa: E402


def main():
    v = version()
    print("geektls version:", json.dumps(v))
    assert v["abi"] == 1, "abi mismatch: %r" % (v,)
    print("python smoke OK")


if __name__ == "__main__":
    main()
