"""P1-T8 probe：打一个 chrome_150 请求到 nginx /ngf-debug，完整打印返回 JSON、
selfcheck 与 describe_preset，用于研究 nginx 采集端字段口径（GREASE/padding/ALPS 等）。
非测试文件，一次性研究用。
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "bindings", "python"))

import geektls

URL = "https://127.0.0.1:8443/ngf-debug"


def main():
    print("=== describe_preset(chrome_150) ===")
    desc = geektls.describe_preset("chrome_150")
    print(json.dumps(desc, indent=2, ensure_ascii=False, sort_keys=True))

    with geektls.Session(impersonate="chrome_150", verify=False, timeout=15) as s:
        r = s.get(URL)
        print("\n=== response status=%d used_protocol=%s ===" % (r.status_code, r.used_protocol))
        print("=== response.selfcheck ===")
        print(json.dumps(r.selfcheck, indent=2, ensure_ascii=False, sort_keys=True))
        body = r.json()
        print("=== nginx $http_fingerprint_json ===")
        print(json.dumps(body, indent=2, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
