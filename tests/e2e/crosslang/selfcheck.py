"""跨语言一致性用：对 echo 发一个请求，stdout 打印 selfcheck JSON。
用法：selfcheck.py <preset> <base_url>
"""

import json
import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "bindings", "python"))

from geektls import Session  # noqa: E402

preset, base = sys.argv[1], sys.argv[2]

with Session(impersonate=preset, insecure_skip_verify=True) as s:
    r = s.get(base + "/echo")
    print(json.dumps({
        "ja3_hash": r.selfcheck.get("ja3_hash", ""),
        "ja4": r.selfcheck.get("ja4", ""),
        "proto": r.used_protocol,
    }))
    r.close()
