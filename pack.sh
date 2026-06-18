#!/usr/bin/env bash
set -euo pipefail
SRC="natssl"
mkdir -p "$SRC/docs"

# ВНИМАНИЕ: сюда нужно положить .go-файлы из предыдущего ответа:
#   main.go config.go recovery.go cache.go ca.go store.go
#   server.go client.go promote.go netutil.go install.go
# Этот скрипт упаковывает уже существующие файлы каталога.

REQUIRED=(main.go config.go recovery.go cache.go ca.go store.go \
          server.go client.go client_issue.go promote.go netutil.go install.go \
          go.mod Makefile build.sh README.md docs/DEPLOYMENT.md)

missing=0
for f in "${REQUIRED[@]}"; do
  if [[ ! -f "$SRC/$f" ]]; then
    echo "MISSING: $SRC/$f"; missing=1
  fi
done
[[ $missing -eq 0 ]] || { echo "Положите недостающие файлы и повторите."; exit 1; }

tar -czf natssl-src.tar.gz "$SRC"
sha256sum natssl-src.tar.gz
echo ">> archive ready: natssl-src.tar.gz"
