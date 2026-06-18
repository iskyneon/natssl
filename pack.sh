#!/usr/bin/env bash
set -euo pipefail

OUT="natssl-src.tar.gz"

# Prefer `git archive` when inside a clean git repo: it packs exactly the
# tracked files and never goes stale when new source files are added.
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo ">> packing tracked files via git archive"
  git archive --format=tar.gz --prefix="natssl/" -o "$OUT" HEAD
  echo ">> done: $OUT"
  ls -lah "$OUT"
  exit 0
fi

# Fallback: explicit file list (kept in sync manually).
echo ">> not a git repo — packing explicit file list"
FILES=(
  ca.go
  cache.go
  client.go
  client_issue.go
  config.go
  install.go
  main.go
  migrate.go
  netcheck.go
  netutil.go
  promote.go
  recovery.go
  register.go
  server.go
  store.go

  config.master.yaml
  config.client.yaml
  go.mod
  go.sum

  build.sh
  pack.sh
  Makefile

  README.md
  docs/DEPLOYMENT.md

  .github/workflows/ci.yml

  natssl-master.service
  natssl-client.service
)

tar -czf "$OUT" --transform 's,^,natssl/,' "${FILES[@]}"
echo ">> done: $OUT"
ls -lah "$OUT"
