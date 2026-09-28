#!/usr/bin/env python3
"""把第三方指纹集 tls_config 的全部配置导出为 JSON 快照。

用法：
    python3 dump.py <tls_config 包所在目录> <输出 json 路径>

其中 <tls_config 包所在目录> 指含 `tls_config/` 子目录与 setup.py 的那一层，
例如 …/tls_config-0.0.2/tls_config-0.0.2。

为什么要导出快照而不是直接读 .py：那份数据是**第三方**的，导入流程必须可复现、
可审计——快照入库 + 转换器（Go）入库，任何人可重跑得到同样结果。
"""
import json
import os
import sys


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    pkg_parent, out_path = sys.argv[1], sys.argv[2]
    sys.path.insert(0, pkg_parent)

    import tls_config as T
    from tls_config.config import TLSConfig

    out = {}
    for name in dir(T):
        if not name.startswith("TLS_"):
            continue
        obj = getattr(T, name)
        if not isinstance(obj, TLSConfig):
            continue
        d = obj.toJSON()
        d["_const"] = name
        out[name] = d

    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=1, sort_keys=True)

    fam = {}
    for n in out:
        parts = n.split("_")
        fam[parts[1] if len(parts) > 1 else "?"] = fam.get(parts[1], 0) + 1
    print("configs:", len(out))
    print("by family:", dict(sorted(fam.items())))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
