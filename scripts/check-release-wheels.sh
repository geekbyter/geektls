#!/usr/bin/env bash
# 上传前的发布物白名单校验（给"本地手动编译 + 手动上传"这条路径用的防线）。
#
# 为什么需要它：**PyPI 没有 yank 的 API**（只能去网页 Manage → Releases → Yank 点），
# 一旦传错平台标签，就只能在网页上补救。0.1.4 就出过一次：本地 WSL 构建的
# manylinux_2_34_x86_64 混进同一个版本，而现代 glibc 上 pip 会**优先选它**、
# 而不是 CI 在 manylinux_2_28 容器里构建的那个（标签不假、但兼容面更小的那个被绕过）。
#
# 用法：
#   bash scripts/check-release-wheels.sh                     # 默认扫 bindings/python/dist*/*.whl
#   bash scripts/check-release-wheels.sh path/to/dist/*.whl
#   ALLOWED_TAGS="manylinux_2_28_x86_64" bash scripts/check-release-wheels.sh <wheel>
#
# 四项检查：
#   1) 文件名版本号 == 版本源（bindings/python/pyproject.toml）——挡住旧版本残留；
#   2) 平台标签在白名单内（默认 = CI 矩阵那 5 个）——挡住 manylinux_2_34 / py3-none-any；
#   3) 包内原生库恰好一个，且类型与平台一致（linux→.so / macos→.dylib / win→.dll）；
#   4) Linux 轮子：包内 .so 引用的 GLIBC 符号不得高于标签基线（manylinux_2_28 ⇒ ≤ 2.28）。
#      ⚠️ 这条最关键：在 glibc 2.4x 的发行版上本地构建、再打 manylinux_2_28 标签，
#      得到的是**谎标签**——只有 manylinux 容器里构建的才是真 2_28（CI 就是这么做的）。
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ALLOWED_TAGS="${ALLOWED_TAGS:-manylinux_2_28_x86_64 manylinux_2_28_aarch64 macosx_11_0_arm64 macosx_11_0_x86_64 win_amd64}"

PY=""
for c in python3 python py; do command -v "$c" >/dev/null 2>&1 && { PY="$c"; break; }; done
[ -n "$PY" ] || { echo "需要 python 来读 wheel 内的元数据/原生库" >&2; exit 2; }

VER="$(sed -n 's/^version = "\([^"]*\)".*/\1/p' "$ROOT/bindings/python/pyproject.toml" | head -1 | tr -d '\r')"
[ -n "$VER" ] || { echo "读不到版本源 bindings/python/pyproject.toml" >&2; exit 2; }

if [ "$#" -gt 0 ]; then
  FILES=("$@")
else
  shopt -s nullglob
  FILES=("$ROOT"/bindings/python/dist*/*.whl)
fi

echo "版本源：$VER"
echo "白名单：$ALLOWED_TAGS"
echo "待检文件：${#FILES[@]} 个"
echo

rc=0
checked=0
for f in "${FILES[@]}"; do
  # 显式传进来的实参若没被 shell 展开（如带引号的 "dist/*.whl"）会走到这里：
  # 必须报错，绝不能静默跳过——"零文件 ⇒ 全部通过"对发布前检查是危险的假阳性。
  if [ ! -e "$f" ]; then
    echo "  ❌ $f：文件不存在（glob 没展开？）"
    rc=1
    continue
  fi
  checked=$((checked + 1))
  base="$(basename "$f")"
  fail() { echo "  ❌ $base：$1"; rc=1; }

  # 1) 版本号
  tag="${base#geektls-$VER-py3-none-}"
  if [ "$tag" = "$base" ]; then
    fail "文件名不符合 geektls-$VER-py3-none-<标签>.whl（版本号与版本源不一致？）"
    continue
  fi
  tag="${tag%.whl}"

  # 2) 白名单
  case " $ALLOWED_TAGS " in
    *" $tag "*) ;;
    *) fail "平台标签 '$tag' 不在白名单里（拒绝上传；PyPI 只能网页 yank，别传错）"; continue ;;
  esac

  case "$tag" in
    manylinux_2_28_x86_64|manylinux_2_28_aarch64) kind=so  want="manylinux_2_28" ;;
    macosx_11_0_arm64|macosx_11_0_x86_64)          kind=dylib want="" ;;
    win_amd64)                                     kind=dll  want="" ;;
    *)                                             kind=""    want="" ;;
  esac

  # 3) 包内原生库 + 4) glibc 基线（都交给 python 处理，避免 unzip 的可移植性问题）
  out="$("$PY" - "$f" "$kind" "$want" <<'PY'
import os, re, subprocess, sys, tempfile, zipfile

wheel, kind, want = sys.argv[1], sys.argv[2], sys.argv[3]
z = zipfile.ZipFile(wheel)
libs = [n for n in z.namelist() if n.endswith((".so", ".dll", ".dylib"))]
if len(libs) != 1:
    print("FAIL 包内原生库数量=%d（应为 1：%s）" % (len(libs), libs))
    raise SystemExit
if kind and not libs[0].endswith("." + kind):
    print("FAIL 包内原生库 %s 与平台标签不符（期望 .%s）" % (libs[0], kind))
    raise SystemExit
if not want:
    print("OK 包内原生库 %s（该平台不做 glibc 基线检查）" % libs[0])
    raise SystemExit

with tempfile.TemporaryDirectory() as td:
    p = os.path.join(td, os.path.basename(libs[0]))
    with open(p, "wb") as fh:
        fh.write(z.read(libs[0]))
    if subprocess.run(["objdump", "-T", p], capture_output=True).returncode != 0:
        print("SKIP 无 objdump，跳过 glibc 基线检查（%s）" % libs[0])
        raise SystemExit
    syms = subprocess.run(["objdump", "-T", p], capture_output=True, text=True).stdout
vers = sorted({v for v in re.findall(r"GLIBC_([0-9.]+)", syms)},
              key=lambda s: [int(x) for x in s.split(".")])
top = vers[-1] if vers else "0"
lim = tuple(int(x) for x in want.split("_")[-1].split("."))
too_new = [v for v in vers if tuple(int(x) for x in v.split(".")) > lim]
if too_new:
    print("FAIL 最高 GLIBC=%s，超过 %s 基线（越线符号：%s）⇒ 这是**谎标签**，"
          "真 2_28 必须在 manylinux_2_28 容器里构建" % (top, want, ",".join(too_new)))
else:
    print("OK 包内原生库 %s；最高 GLIBC=%s ≤ %s" % (libs[0], top, want))
PY
)"
  case "$out" in
    OK*)   echo "  ✅ $base：${out#OK }" ;;
    SKIP*) echo "  ⚠️  $base：${out#SKIP }" ;;
    FAIL*) fail "${out#FAIL }" ;;
    *)     fail "校验异常：$out" ;;
  esac
done

echo
if [ "$checked" -eq 0 ]; then
  echo "没有检查到任何 wheel（路径展开为空？）⇒ 当作失败处理。" >&2
  exit 1
fi
if [ "$rc" -eq 0 ]; then
  echo "全部通过（$checked 个文件），可以上传。"
else
  echo "有文件未通过 ⇒ 不要上传（PyPI 没有 yank API，传错只能网页补救）。"
fi
exit "$rc"
