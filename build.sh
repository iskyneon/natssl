#!/usr/bin/env bash
set -euo pipefail

VERSION="${VERSION:-1.0.0-oss}"
OUT="dist"

# Pure-Go build (modernc.org/sqlite) -> CGO must be OFF for clean cross-compile.
export CGO_ENABLED=0

rm -rf "$OUT"
mkdir -p "$OUT"

PLATFORMS=("linux amd64" "linux arm64")

for p in "${PLATFORMS[@]}"; do
	read -r GOOS GOARCH <<<"$p"
	NAME="natssl-${VERSION}-${GOOS}-${GOARCH}"
	echo ">> building ${NAME}"
	GOOS="$GOOS" GOARCH="$GOARCH" go build \
		-trimpath \
		-ldflags "-s -w -X main.version=${VERSION}" \
		-o "${OUT}/${NAME}" \
		.
	( cd "$OUT" && tar -czf "${NAME}.tar.gz" "${NAME}" && rm -f "${NAME}" )
done

echo ">> checksums"
( cd "$OUT" && sha256sum *.tar.gz > SHA256SUMS.txt )

echo ">> done:"
ls -lah "$OUT"
