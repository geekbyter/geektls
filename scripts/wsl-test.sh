#!/usr/bin/env bash
# 在 WSL(Linux) 侧运行 geektls 的 Go 测试（Linux 才能验证的路径：
# TCP raw/sockopt、平台构建标签、以及后续 nginx 采集端闭环）。
#
# 用法（Windows 侧）：
#   wsl -d Ubuntu -- bash /mnt/d/work/tls/geektls/scripts/wsl-test.sh              # core 全部测试
#   wsl -d Ubuntu -- bash /mnt/d/work/tls/geektls/scripts/wsl-test.sh ./tcp/...    # 指定包
#   wsl -d Ubuntu -- bash /mnt/d/work/tls/geektls/scripts/wsl-test.sh -tags external ./...
#
# 首次运行会自动安装用户态 Go 到 ~/.local/go（无需 sudo）。
set -euo pipefail

GO_VERSION="${GO_VERSION:-1.27.0}"
GO_ROOT="${GO_ROOT:-$HOME/.local/go}"

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CORE_DIR="$REPO_DIR/core"
E2E_DIR="$REPO_DIR/tests/e2e"

ensure_go() {
  if [ -x "$GO_ROOT/bin/go" ]; then
    echo "[go] using $("$GO_ROOT/bin/go" version)"
    return
  fi
  case "$(uname -m)" in
    x86_64)  goarch=amd64 ;;
    aarch64) goarch=arm64 ;;
    *) echo "[go] unsupported arch $(uname -m)"; exit 1 ;;
  esac
  echo "[go] installing go${GO_VERSION} (${goarch}) into $GO_ROOT ..."
  mkdir -p "$HOME/.local"
  tarball="$HOME/.local/go${GO_VERSION}.linux-${goarch}.tar.gz"
  curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${goarch}.tar.gz" -o "$tarball"
  rm -rf "$GO_ROOT"
  tar -C "$HOME/.local" -xzf "$tarball"
  rm -f "$tarball"
  echo "[go] installed: $("$GO_ROOT/bin/go" version)"
}

ensure_go
export PATH="$GO_ROOT/bin:$PATH"
export GOFLAGS="${GOFLAGS:-}"
# Windows 挂载盘上的构建缓存放到 Linux 侧，快且避开权限位问题
export GOCACHE="${GOCACHE:-$HOME/.cache/go-build}"
export GOMODCACHE="${GOMODCACHE:-$HOME/go/pkg/mod}"

run_core() {
  echo
  echo "=== core tests ($CORE_DIR) ==="
  cd "$CORE_DIR"
  go build ./...
  go test "${EXTRA_ARGS[@]}" ./...
}

run_e2e() {
  echo
  echo "=== e2e tests ($E2E_DIR) ==="
  cd "$E2E_DIR"
  go test "${EXTRA_ARGS[@]}" ./...
}

EXTRA_ARGS=("$@")
run_core
if [ "${NGF_CORE_ONLY:-no}" != "yes" ]; then
  run_e2e
fi

echo
echo "[wsl-test] done"
