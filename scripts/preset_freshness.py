#!/usr/bin/env python3
"""预设新鲜度体检：我们的最高版本 vs 上游 stable，落后就红（审计 A12）。

背景：`docs/maintenance.md` 定的是"Chrome 2 周人工 SLA"，但没有任何机制能发现
"上游已发新版而 builtin 最高还是 154"。本脚本把这件事变成一条命令 + 一个 weekly job。

覆盖范围（诚实声明）：只自动化**有稳定 JSON feed 且无需 key** 的两族——
Chrome 与 Firefox。Edge（Chromium 同列车，跟着 Chrome 的差距看）、Safari / Opera /
各家国产浏览器**没有机器可读的 stable feed**，仍走 `docs/maintenance.md` 的人工 SLA；
curl / okhttp / IE 这类"工具型"预设不参与新鲜度判定（它们不随浏览器版本变）。

用法：
    python scripts/preset_freshness.py                 # 人读表格，落后则退出码 1
    python scripts/preset_freshness.py --quiet         # 只打印落后项
    python scripts/preset_freshness.py --tolerance 2   # 落后 >=2 个大版本才算红
    python scripts/preset_freshness.py --json out.json # 机器可读结果

网络不可达 ⇒ 退出码 2（**不是** 0）：CI 里"取不到 feed"不能伪装成"没落后"。
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.request
import urllib.error

BUILTIN = "core/profiles/builtin"


def _chrome_stable(d: dict) -> str:
    # channel 键首字母大写（"Stable"），且顺序不保证 ⇒ 按大小写不敏感找
    for k, v in d["channels"].items():
        if str(k).lower() == "stable":
            return v["version"]
    raise KeyError("stable channel")


FEEDS = {
    # family: (feed url, 从 JSON 里取 stable 版本串的函数)
    "chrome": (
        "https://googlechromelabs.github.io/chrome-for-testing/last-known-good-versions.json",
        _chrome_stable,
    ),
    "firefox": (
        "https://product-details.mozilla.org/1.0/firefox_versions.json",
        lambda d: d["LATEST_FIREFOX_VERSION"],
    ),
}
# 不参与判定的族：工具型客户端（版本由自身发布节奏决定，与浏览器列车无关）
SKIP_FAMILIES = {"curl", "ie", "powershell", "postmanruntime", "charles", "fiddler",
                 "reqable", "wechat", "mqqbrowser", "qqbrowser", "okhttp"}


def preset_major(name: str) -> int | None:
    """从预设名取**大版本**。只看紧跟族名的前两个数字段并取较大者：

    chrome_154_windows → 154；chrome_101_109_windows（区间预设）→ 109；
    chrome_122_0_6261_95_windows → 122（后面的构建号不参与）；
    safari_18_6_macos → 18。
    """
    toks = name.split("_")
    nums = []
    for t in toks[1:]:
        if re.fullmatch(r"\d+", t):
            nums.append(int(t))
        else:
            break
    return max(nums[:2]) if nums else None


def scan_builtin(root: str) -> dict[str, int]:
    """{family: 我们已有的最高大版本}"""
    out: dict[str, int] = {}
    for fn in os.listdir(root):
        if not fn.endswith(".json"):
            continue
        name = fn[:-5]
        fam = name.split("_", 1)[0]
        if fam in SKIP_FAMILIES:
            continue
        v = preset_major(name)
        if v is not None:
            out[fam] = max(out.get(fam, 0), v)
    return out


def fetch_latest(family: str) -> tuple[int, str]:
    url, pick = FEEDS[family]
    with urllib.request.urlopen(url, timeout=25) as resp:
        data = json.load(resp)
    ver = str(pick(data))
    major = int(ver.split(".")[0])
    return major, ver


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--builtin", default=BUILTIN, help="预设目录（默认 core/profiles/builtin）")
    ap.add_argument("--tolerance", type=int, default=1, help="落后多少个 major 才算红（默认 1）")
    ap.add_argument("--quiet", action="store_true", help="只打印落后项")
    ap.add_argument("--json", dest="json_out", help="把结果写成 JSON")
    args = ap.parse_args()

    ours = scan_builtin(args.builtin)
    rows, failures = [], 0
    for family in sorted(FEEDS):
        have = ours.get(family, 0)
        try:
            latest, ver = fetch_latest(family)
        except (urllib.error.URLError, KeyError, ValueError, json.JSONDecodeError) as e:
            print(f"!! {family}: 取不到上游版本（{e}）——按失败处理，「取不到」不等于「没落后」", file=sys.stderr)
            return 2
        behind = latest - have
        status = "BEHIND" if behind >= args.tolerance else "OK"
        if status == "BEHIND":
            failures += 1
        rows.append({"family": family, "ours": have, "latest": latest,
                     "latest_version": ver, "behind": behind, "status": status})

    if not args.quiet or failures:
        print(f"{'family':<9}{'ours':>7}{'upstream stable':>18}{'behind':>8}  verdict")
        for r in rows:
            print(f"{r['family']:<10}{r['ours']:>7}{r['latest_version']:>18}"
                  f"{r['behind']:>8}  {r['status']}")
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump({"rows": rows, "unscored_families": sorted(
                k for k in ours if k not in FEEDS)}, f, ensure_ascii=False, indent=2)

    if failures:
        print(f"\n{failures} 族落后于上游 stable；待采清单见 docs/08、docs/maintenance.md",
              file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
