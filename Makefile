.PHONY: help install dev-install dev setup test test-quick lint lint-fix format format-check vet check fix build run release-snapshot clean all ci
.DEFAULT_GOAL := help

BINARY  := flatcar-vex
PKG     := github.com/flatcar/vex-automation
CMD_DIR := ./cmd/$(BINARY)
BIN_DIR := bin
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X $(PKG)/internal/cli.Version=$(VERSION)

help: ## 📋 Show this help message
	@echo "Available commands:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

install: ## 📦 Download and verify module dependencies
	go mod download
	go mod verify

dev-install: install ## 🛠️ Install / sync dev tool dependencies (via go.mod tool directives)
	go mod tidy

test: ## 🧪 Run tests with coverage
	go tool gotestsum --format=short-verbose -- -race -covermode=atomic -coverprofile=coverage.txt ./...

test-quick: ## ⚡ Run tests without coverage
	go tool gotestsum --format=short -- ./...

lint: ## 🔍 Run linting checks
	go tool golangci-lint run ./...

lint-fix: ## 🔧 Run linting and fix auto-fixable issues
	go tool golangci-lint run --fix ./...

format: ## 🎨 Format code (gofmt + goimports via golangci-lint)
	go tool golangci-lint fmt ./...

format-check: ## ✅ Check formatting without making changes
	go tool golangci-lint fmt --diff ./...

vet: ## 🏷️ Run go vet (type-check equivalent)
	go vet ./...

check: ## 🔎 Run all checks (format-check, lint, vet, test)
	@echo "📝 Checking code formatting..."
	$(MAKE) format-check
	@echo "🔍 Running linting..."
	$(MAKE) lint
	@echo "🏷️  Running go vet..."
	$(MAKE) vet
	@echo "🧪 Running tests..."
	$(MAKE) test
	@echo "✅ All checks passed!"

fix: ## 🔧 Fix formatting and auto-fixable linting issues
	@echo "🔧 Fixing code formatting..."
	$(MAKE) format
	@echo "🔧 Fixing linting issues..."
	$(MAKE) lint-fix
	@echo "✅ Code fixes applied!"

build: ## 📦 Build the binary
	mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(BINARY) $(CMD_DIR)

run: ## 🚀 Run the CLI (pass args with ARGS='...')
	go run $(CMD_DIR) $(ARGS)

release-snapshot: ## 🎁 Build a local release snapshot with goreleaser
	go tool goreleaser release --snapshot --clean

clean: ## 🧹 Clean build artifacts
	rm -rf $(BIN_DIR) dist coverage.txt coverage.html

all: ## 🎯 Run complete workflow (setup, fix, check, build)
	@echo "🎯 Running complete workflow..."
	$(MAKE) dev-install
	$(MAKE) fix
	$(MAKE) check
	$(MAKE) build
	@echo "🎉 Complete workflow finished successfully!"

dev: dev-install ## 🚀 Alias for dev-install
setup: dev-install ## ⚙️ Alias for dev-install
ci: check ## 🤖 Run all CI checks locally
