VERSION ?= 1.0.0-oss
BINARY  := natssl
OUT     := dist

# Pure-Go SQLite (modernc.org/sqlite): keep CGO off for clean cross-compile.
export CGO_ENABLED=0

LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: all build release clean test tidy vet fmt run-master run-client pack

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

## test: run unit tests
test:
	go test ./...

## tidy: sync go.mod / go.sum
tidy:
	go mod tidy

## vet: static checks
vet:
	go vet ./...

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
