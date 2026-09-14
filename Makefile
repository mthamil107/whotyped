# whotyped build helpers. Pure Go, CGO_ENABLED=0; only gopkg.in/yaml.v3.
MODULE   := github.com/mthamil107/whotyped
BIN      := whotyped
DIST     := dist
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT   ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE     ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS  := -s -w \
  -X $(MODULE)/internal/version.Version=$(VERSION) \
  -X $(MODULE)/internal/version.Commit=$(COMMIT) \
  -X $(MODULE)/internal/version.Date=$(DATE)
GOFLAGS  := -trimpath
export CGO_ENABLED = 0

.PHONY: all build test vet fmt-check lint cross release-snapshot docker-lab simulate clean help

all: fmt-check vet test build

help: ## list targets
	@grep -E '^[a-z-]+:.*##' $(MAKEFILE_LIST) | sed 's/:.*## /\t/' | sort

build: ## build ./whotyped for the host OS
	go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $(BIN)$(shell go env GOEXE) ./cmd/whotyped

test: ## go test ./... (add RACE=1 for -race; needs cgo)
	go test $(if $(RACE),-race) ./...

vet: ## go vet ./...
	go vet ./...

fmt-check: ## fail when gofmt would change a file
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

lint: vet ## stdlib-only lint (go vet)

cross: ## linux amd64 + arm64 binaries into dist/
	@mkdir -p $(DIST)
	GOOS=linux GOARCH=amd64 go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $(DIST)/$(BIN)-linux-amd64 ./cmd/whotyped
	GOOS=linux GOARCH=arm64 go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $(DIST)/$(BIN)-linux-arm64 ./cmd/whotyped
	@ls -l $(DIST)

release-snapshot: ## goreleaser snapshot build (archives, deb, rpm) without publishing
	goreleaser release --snapshot --clean --skip=sign,sbom

simulate: ## offline simulation of every scenario
	@for s in $$(go run ./cmd/whotyped simulate --offline --scenario list --json | grep -o '"name": *"[^"]*"' | cut -d'"' -f4); do \
	  go run ./cmd/whotyped simulate --offline --scenario $$s >/dev/null && echo "PASS $$s" || echo "FAIL $$s"; done

docker-lab: ## bring up the lab sshd container (lab/docker-compose.yml)
	@if [ -f lab/docker-compose.yml ]; then docker compose -f lab/docker-compose.yml up -d --build; \
	 else echo "lab/docker-compose.yml not present"; exit 1; fi

clean: ## remove build outputs
	rm -rf $(DIST) $(BIN) $(BIN).exe
