"""P1-T8 probe：7 预设逐个打 nginx /ngf-debug（localhost，带 SNI），完整落盘 JSON。
输出到 probe_matrix.json，供 verify_l2.py 断言设计参考。非测试文件。
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "bindings", "python"))

import geektls

URL = "https://localhost:8443/ngf-debug"
PRESETS = ["chrome_131", "chrome_133", "chrome_150", "firefox_120", "firefox_135",
           "safari_16", "safari_18"]


def main():
    out = {}
    for name in PRESETS:
        desc = geektls.describe_preset(name)
        try:
            with geektls.Session(impersonate=name, verify=False, timeout=15) as s:
                r = s.get(URL)
                body = r.json()
                out[name] = {
                    "status": r.status_code,
                    "used_protocol": r.used_protocol,
                    "selfcheck": r.selfcheck,
                    "nginx": body,
                    "describe": desc,
                }
                print("%-12s status=%d proto=%s ja4(nginx)=%s ja4(self)=%s" % (
                    name, r.status_code, r.used_protocol,
                    body.get("ja4"), r.selfcheck.get("ja4")))
        except Exception as exc:
            out[name] = {"error": repr(exc), "describe": desc}
            print("%-12s ERROR %r" % (name, exc))
    dst = os.path.join(os.path.dirname(__file__), "probe_matrix.json")
    with open(dst, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, ensure_ascii=False, sort_keys=True)
    print("written:", dst)


if __name__ == "__main__":
    main()
