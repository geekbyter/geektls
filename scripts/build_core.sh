#!/usr/bin/env bash
# 构建 geektls core 的 c-shared 动态库（Git Bash / Linux / macOS 通用）。
# 产物：Windows → build/geektls.dll；Linux → build/libgeektls.so；macOS → build/libgeektls.dylib
set -euo pipefail
cd "$(dirname "$0")/.."

case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*) LIB=geektls.dll ;;
  Darwin*)              LIB=libgeektls.dylib ;;
  *)                    LIB=libgeektls.so ;;
esac

mkdir -p build
(cd core && go build -buildmode=c-shared -o "../build/$LIB" ./ffi)
echo "built: build/$LIB"
