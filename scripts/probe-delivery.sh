#!/usr/bin/env bash
# 外部通信なしの2CPU/1GiBコンテナで合成HTTPS配信を再現する。
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p var
umask 077
CGO_ENABLED=0 mise exec -- go build -trimpath -o var/trafficprobe ./tools/trafficprobe
docker run --rm --network none --cpus 2 --memory 1g --memory-swap 1g \
  --pids-limit 2048 --read-only -e GOMEMLIMIT=768MiB \
  -v "$PWD/var/trafficprobe:/probe:ro" --entrypoint /probe \
  oimobbs-validation:local > var/delivery-trafficprobe.json
