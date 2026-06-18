#!/usr/bin/env bash
set -euo pipefail

VERSION="${VERSION:-1.0.8-oss}"
COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo nogit)"
DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
OUT="dist"

# Pure-Go build (modernc.org/sqlite) -> CGO must be OFF for clean cross-compile.
export CGO_ENABLED=0

# NOTE: variables live in package main as Version / Commit / BuildDate
# (capitalized). The previous "-X main.version" silently injected nothing.
LDFLAGS="-s -w \
  -X main.Version=${VERSION} \
  -X main.Commit=${COMMIT} \
  -X main.BuildDate=${DATE}"

rm -rf "$OUT"
mkdir -p "$OUT"

PLATFORMS=("linux amd64" "linux arm64" "darwin amd64" "darwin arm64")

for p in "${PLATFORMS[@]}"; do
  read -r GOOS GOARCH <<<"$p"
  NAME="natssl-${VERSION}-${GOOS}-${GOARCH}"
  echo ">> building ${NAME}"
  GOOS="$GOOS" GOARCH="$GOARCH" go build \
    -trimpath \
    -ldflags "$LDFLAGS" \
    -o "${OUT}/${NAME}" \
    .
  ( cd "$OUT" && tar -czf "${NAME}.tar.gz" "${NAME}" && rm -f "${NAME}" )
done

echo ">> checksums"
( cd "$OUT" && sha256sum *.tar.gz > SHA256SUMS.txt )

echo ">> done:"
ls -lah "$OUT"
