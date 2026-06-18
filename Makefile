VERSION ?= 1.0.8-oss
COMMIT  := $(shell git rev-parse --short HEAD 2>/dev/null || echo nogit)
DATE    := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
BINARY  := natssl
OUT     := dist

# Pure-Go SQLite (modernc.org/sqlite): keep CGO off for clean cross-compile.
export CGO_ENABLED=0

# Capitalized names: package main uses Version / Commit / BuildDate.
LDFLAGS := -s -w \
  -X main.Version=$(VERSION) \
  -X main.Commit=$(COMMIT) \
  -X main.BuildDate=$(DATE)

.PHONY: all build release clean test tidy vet staticcheck fmt run-master run-client pack ci

all: build

## build: compile a native binary into ./$(BINARY)
build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) .

## release: cross-compile amd64 + arm64 tarballs into ./$(OUT)
release:
	./build.sh

## pack: archive the source tree into natssl-src.tar.gz
pack:
	./pack.sh

## test: run unit tests (race detector on)
test:
	go test -race ./...

## tidy: sync go.mod / go.sum
tidy:
	go mod tidy

## vet: static checks
vet:
	go vet ./...

## staticcheck: deeper linting (installed on demand)
staticcheck:
	@command -v staticcheck >/dev/null 2>&1 || go install honnef.co/go/tools/cmd/staticcheck@latest
	staticcheck ./...

## ci: the full gate run locally (mirrors .github/workflows/ci.yml)
ci: tidy vet staticcheck test
	@git diff --exit-code go.mod go.sum

## fmt: format all sources
fmt:
	gofmt -s -w .

## run-master: run locally as master (needs root for :443)
run-master: build
	sudo ./$(BINARY) --mode=master --config=./config.master.yaml

## run-client: run locally as client
run-client: build
	sudo ./$(BINARY) --mode=client --config=./config.client.yaml

## clean: remove build artifacts
clean:
	rm -rf $(BINARY) $(OUT) natssl-src.tar.gz
