#!/usr/bin/env bash
# Linux 侧（WSL）开发环境盘点。用法：
#   wsl -d Ubuntu -- bash /mnt/d/work/tls/geektls/scripts/wsl-env-check.sh
set -u

echo "=== OS ==="
. /etc/os-release 2>/dev/null && echo "$PRETTY_NAME $(uname -m)"
echo "cpus=$(nproc) mem=$(free -m | awk '/Mem:/{print $2}')MB"

echo
echo "=== toolchain ==="
for c in go python3 pip3 gcc cc git patch make cmake pkg-config tcpdump; do
  printf '%-12s ' "$c"
  command -v "$c" || echo MISSING
done

echo
echo "=== versions ==="
go version 2>/dev/null || true
python3 --version 2>/dev/null || true
gcc --version 2>/dev/null | head -1 || true

echo
echo "=== openssl headers (nginx TLS build) ==="
ls /usr/include/openssl/ssl.h 2>/dev/null || echo "libssl-dev MISSING"
pkg-config --modversion openssl 2>/dev/null || true

echo
echo "=== repo mount ==="
ls -d /mnt/d/work/tls /mnt/d/work/tls/geektls 2>/dev/null || echo "repo not reachable from WSL"
