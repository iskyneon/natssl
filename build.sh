#!/usr/bin/env bash
set -euo pipefail

BINARY="natssl"
VERSION="${VERSION:-1.0.0-oss}"
COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo nogit)"
DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
DIST="dist"

export CGO_ENABLED=0
LDFLAGS="-s -w -X main.Version=${VERSION} -X main.Commit=${COMMIT} -X main.BuildDate=${DATE}"

PLATFORMS=("linux/amd64" "linux/arm64")

echo ">> go mod tidy"
go mod tidy

rm -rf "$DIST"; mkdir -p "$DIST"

for p in "${PLATFORMS[@]}"; do
  OS="${p%/*}"; ARCH="${p#*/}"
  OUT="${BINARY}-${VERSION}-${OS}-${ARCH}"
  echo ">> building ${OS}/${ARCH}"
  GOOS="$OS" GOARCH="$ARCH" go build -trimpath -ldflags="$LDFLAGS" -o "${DIST}/${OUT}" .
  tar -C "$DIST" -czf "${DIST}/${OUT}.tar.gz" "$OUT"
  rm -f "${DIST}/${OUT}"
done

( cd "$DIST" && sha256sum *.tar.gz > SHA256SUMS.txt )
echo ">> done:"
ls -lh "$DIST"
cat "${DIST}/SHA256SUMS.txt"
