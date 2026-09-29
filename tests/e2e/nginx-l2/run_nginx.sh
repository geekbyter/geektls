#!/usr/bin/env bash
# P1-T8 L2 终审：在 WSL 内启动 nginx 指纹套件（本地 prefix，免 sudo）
set -euo pipefail

SUITE="${SUITE:-$HOME/nginx-suite}"
BUILD="$(cat "$SUITE/.work/build-path" 2>/dev/null || echo "$SUITE/.work/build-1.27.5")"
RUNTIME="$HOME/nginx-runtime"

mkdir -p "$RUNTIME"/{logs,conf}
cd "$RUNTIME"

# 自签证书（幂等；nginx 以 conf 目录为基准解析相对路径）
if [ ! -f conf/cert.pem ]; then
    openssl req -x509 -newkey rsa:2048 -keyout conf/key.pem -out conf/cert.pem \
        -days 3650 -nodes -subj "/CN=localhost" >/dev/null 2>&1
fi

# 配置从仓库拷贝（允许调用方覆盖）
cp /mnt/d/work/tls/geektls/tests/e2e/nginx-l2/nginx.conf conf/nginx.conf

# 停旧起新
[ -f logs/nginx.pid ] && kill "$(cat logs/nginx.pid)" 2>/dev/null || true
sleep 0.3

"$BUILD/nginx" -p "$RUNTIME" -c conf/nginx.conf -t
"$BUILD/nginx" -p "$RUNTIME" -c conf/nginx.conf
sleep 0.5
curl -sk -o /dev/null -w "nginx up, https status=%{http_code}\n" https://127.0.0.1:8443/
