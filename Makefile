# ============================================================
#  NATSSL — Makefile (cross-compilation amd64 / arm64)
# ============================================================
BINARY      := natssl
VERSION     := 1.0.0-oss
COMMIT      := $(shell git rev-parse --short HEAD 2>/dev/null || echo "nogit")
DATE        := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
DIST        := dist

# CGO выключен -> чистый статический бинарник (modernc.org/sqlite — pure Go)
export CGO_ENABLED=0

LDFLAGS := -s -w \
	-X 'main.Version=$(VERSION)' \
	-X 'main.Commit=$(COMMIT)' \
	-X 'main.BuildDate=$(DATE)'

# Список целей: GOOS/GOARCH
PLATFORMS := linux/amd64 linux/arm64

.PHONY: all clean tidy build release checksums help

all: release ## Собрать релизы под все платформы

help: ## Показать список целей
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-12s\033[0m %s\n",$$1,$$2}'

tidy: ## go mod tidy
	go mod tidy

build: tidy ## Локальная сборка под текущую платформу
	go build -trimpath -ldflags="$(LDFLAGS)" -o $(BINARY) .

release: tidy ## Кросс-компиляция под amd64 и arm64
	@mkdir -p $(DIST)
	@for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; \
		out=$(DIST)/$(BINARY)-$(VERSION)-$$os-$$arch; \
		echo ">> building $$os/$$arch"; \
		GOOS=$$os GOARCH=$$arch go build -trimpath \
			-ldflags="$(LDFLAGS)" -o $$out . ; \
		tar -C $(DIST) -czf $$out.tar.gz $$(basename $$out) ; \
		rm -f $$out ; \
	done
	@$(MAKE) checksums

checksums: ## Посчитать SHA-256 для артефактов
	@cd $(DIST) && sha256sum *.tar.gz > SHA256SUMS.txt && \
		echo ">> checksums:" && cat SHA256SUMS.txt

clean: ## Очистить артефакты
	rm -rf $(DIST) $(BINARY)
