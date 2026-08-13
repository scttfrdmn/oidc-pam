.PHONY: build build-pam skip-pam test install clean lint fmt vet tidy verify-linux help

# Build variables
BINARY_DIR := bin
PAM_MODULE := pam_oidc.so
BROKER_BINARY := oidc-auth-broker
HELPER_BINARY := oidc-pam-helper
ADMIN_BINARY := oidc-admin

# Version information
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_DATE ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
GIT_COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")

# Go build flags
GO_BUILD_FLAGS := -ldflags="-s -w -X main.version=$(VERSION) -X main.buildDate=$(BUILD_DATE) -X main.gitCommit=$(GIT_COMMIT)" -trimpath
GO_TEST_FLAGS := -race -coverprofile=coverage.out

# The PAM module is the one artifact that cannot be built off Linux — its C
# bridge needs Linux-PAM and json-c. `make build` therefore skips it elsewhere
# rather than failing, so the rest of the tree still builds on a developer's Mac;
# `make build-pam` invoked directly always refuses, and CI builds on Linux.
# The pinned golangci-lint version, single-sourced from .golangci-version so the
# CI Lint job, the verification container and a local `make lint` cannot disagree.
GOLANGCI_LINT_VERSION := $(shell tr -d '[:space:]' < .golangci-version)

GOOS := $(shell go env GOOS)
ifeq ($(GOOS),linux)
PAM_MODULE_TARGET := build-pam
else
PAM_MODULE_TARGET := skip-pam
endif

# Default target
all: build

## Build all binaries (the PAM module only on Linux)
build: build-broker build-helper build-admin $(PAM_MODULE_TARGET)

skip-pam:
	@echo "Skipping the PAM module: it is Linux-only (GOOS=$(GOOS)). Use 'make verify-linux'."

## Build authentication broker daemon
build-broker:
	@echo "Building authentication broker..."
	@mkdir -p $(BINARY_DIR)
	go build $(GO_BUILD_FLAGS) -o $(BINARY_DIR)/$(BROKER_BINARY) ./cmd/broker

## Build PAM module (Linux only; verifies the result is loadable)
build-pam:
	@echo "Building PAM module..."
	@# The module's C bridge needs Linux-PAM (<security/pam_ext.h>) and json-c,
	@# which macOS does not have, so the cgo in cmd/pam-module is behind a
	@# //go:build linux tag. On another OS this would build a .so with no PAM
	@# entry points in it, which is exactly the failure #140 was about — refuse
	@# instead. Use `make verify-linux` to build and test in the container.
	@if [ "$$(go env GOOS)" != "linux" ]; then \
		echo "build-pam: the PAM module can only be built for Linux (GOOS=$$(go env GOOS))." >&2; \
		echo "           Run 'make verify-linux', or build in a Linux container." >&2; \
		exit 1; \
	fi
	@mkdir -p $(BINARY_DIR)
	CGO_ENABLED=1 go build -buildmode=c-shared $(GO_BUILD_FLAGS) -o $(BINARY_DIR)/$(PAM_MODULE) ./cmd/pam-module
	@# A build that emits a module with no pam_sm_* symbols exits 0, so the only
	@# way to know it worked is to look at the artifact.
	@./scripts/verify-pam-module.sh $(BINARY_DIR)/$(PAM_MODULE)

## Build PAM helper binary
build-helper:
	@echo "Building PAM helper..."
	@mkdir -p $(BINARY_DIR)
	CGO_ENABLED=1 go build $(GO_BUILD_FLAGS) -o $(BINARY_DIR)/$(HELPER_BINARY) ./cmd/pam-helper

## Build admin CLI tool
build-admin:
	@echo "Building admin CLI..."
	@mkdir -p $(BINARY_DIR)
	go build $(GO_BUILD_FLAGS) -o $(BINARY_DIR)/$(ADMIN_BINARY) ./cmd/oidc-admin

## Run all tests
test:
	@echo "Running tests..."
	go test $(GO_TEST_FLAGS) ./...

## Run unit tests only
test-unit:
	@echo "Running unit tests..."
	go test $(GO_TEST_FLAGS) ./pkg/... ./internal/...

## Run integration tests
test-integration:
	@echo "Running integration tests..."
	go test $(GO_TEST_FLAGS) ./test/integration/...

## Run end-to-end tests
test-e2e:
	@echo "Running end-to-end tests..."
	go test $(GO_TEST_FLAGS) ./test/e2e/...

## Verify everything (vet + test + lint, all packages) in a Linux container.
## The cgo/PAM packages cannot be built on macOS, so this is the only way to
## reproduce CI's `pam` and `lint` jobs locally.
verify-linux:
	@echo "Building verification image..."
	docker build -t oidc-pam-verify \
		--build-arg GOLANGCI_LINT_VERSION=$(GOLANGCI_LINT_VERSION) \
		-f test/docker/Dockerfile.verify test/docker
	@echo "Running vet, tests and lint in Linux container..."
	docker run --rm \
		-v "$(CURDIR)":/src \
		-v oidc-pam-gomod:/go/pkg/mod \
		-v oidc-pam-gocache:/root/.cache \
		-w /src oidc-pam-verify \
		sh -c 'go vet ./... \
			&& go test -race ./pkg/... ./internal/... ./cmd/... \
			&& golangci-lint run --timeout=5m ./... \
			&& echo "Building and verifying the PAM module..." \
			&& CGO_ENABLED=1 go build -buildmode=c-shared -trimpath -o /tmp/pam_oidc.so ./cmd/pam-module \
			&& ./scripts/verify-pam-module.sh /tmp/pam_oidc.so'

## Install binaries to system locations
install: build
	@echo "Installing binaries..."
	sudo cp $(BINARY_DIR)/$(PAM_MODULE) /lib/security/
	sudo cp $(BINARY_DIR)/$(BROKER_BINARY) /usr/local/bin/
	sudo cp $(BINARY_DIR)/$(HELPER_BINARY) /usr/local/bin/
	sudo cp $(BINARY_DIR)/$(ADMIN_BINARY) /usr/local/bin/
	sudo cp configs/systemd/oidc-auth-broker.service /etc/systemd/system/
	sudo systemctl daemon-reload
	sudo systemctl enable oidc-auth-broker

## Install development version
install-dev: build
	@echo "Installing development version..."
	sudo cp $(BINARY_DIR)/$(PAM_MODULE) /lib/security/
	sudo cp $(BINARY_DIR)/$(BROKER_BINARY) /usr/local/bin/
	sudo cp $(BINARY_DIR)/$(HELPER_BINARY) /usr/local/bin/
	sudo cp $(BINARY_DIR)/$(ADMIN_BINARY) /usr/local/bin/
	sudo mkdir -p /etc/oidc-auth
	sudo cp configs/examples/broker.yaml /etc/oidc-auth/
	sudo cp configs/systemd/oidc-auth-broker.service /etc/systemd/system/
	sudo systemctl daemon-reload

## Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(BINARY_DIR)
	rm -f coverage.out

## Run linter
lint:
	@echo "Running linter..."
	@# CI runs $(GOLANGCI_LINT_VERSION). A different local version enables a
	@# different set of checks, so a clean local run would not mean a clean CI run
	@# — warn rather than fail, since the version is a local install concern.
	@have=$$(golangci-lint version --short 2>/dev/null || golangci-lint --version 2>/dev/null | grep -o '[0-9]\+\.[0-9]\+\.[0-9]\+' | head -1); \
	want=$$(echo "$(GOLANGCI_LINT_VERSION)" | sed 's/^v//'); \
	if [ -n "$$have" ] && [ "$${have#v}" != "$$want" ]; then \
		echo "warning: golangci-lint $$have installed, but this repo pins v$$want (.golangci-version)." >&2; \
		echo "         Results may differ from CI. 'make verify-linux' always uses the pin." >&2; \
	fi
	golangci-lint run

## Format code
fmt:
	@echo "Formatting code..."
	go fmt ./...

## Run go vet
vet:
	@echo "Running go vet..."
	go vet ./...

## Tidy dependencies
tidy:
	@echo "Tidying dependencies..."
	go mod tidy

## Generate coverage report
coverage: test
	@echo "Generating coverage report..."
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

## Run security scan
security:
	@echo "Running security scan..."
	gosec ./...

## Build Docker image
docker-build:
	@echo "Building Docker image..."
	docker build -t oidc-pam:latest .

## Run Docker container
docker-run:
	@echo "Running Docker container..."
	docker run -it --rm oidc-pam:latest

## Create release build
release: clean
	@echo "Creating release build..."
	@mkdir -p $(BINARY_DIR)
	GOOS=linux GOARCH=amd64 go build $(GO_BUILD_FLAGS) -o $(BINARY_DIR)/$(BROKER_BINARY)-linux-amd64 ./cmd/broker
	GOOS=linux GOARCH=amd64 go build -buildmode=c-shared $(GO_BUILD_FLAGS) -o $(BINARY_DIR)/$(PAM_MODULE)-linux-amd64 ./cmd/pam-module
	GOOS=linux GOARCH=amd64 go build $(GO_BUILD_FLAGS) -o $(BINARY_DIR)/$(HELPER_BINARY)-linux-amd64 ./cmd/pam-helper
	GOOS=linux GOARCH=amd64 go build $(GO_BUILD_FLAGS) -o $(BINARY_DIR)/$(ADMIN_BINARY)-linux-amd64 ./cmd/oidc-admin
	GOOS=linux GOARCH=arm64 go build $(GO_BUILD_FLAGS) -o $(BINARY_DIR)/$(BROKER_BINARY)-linux-arm64 ./cmd/broker
	GOOS=linux GOARCH=arm64 go build -buildmode=c-shared $(GO_BUILD_FLAGS) -o $(BINARY_DIR)/$(PAM_MODULE)-linux-arm64 ./cmd/pam-module
	GOOS=linux GOARCH=arm64 go build $(GO_BUILD_FLAGS) -o $(BINARY_DIR)/$(HELPER_BINARY)-linux-arm64 ./cmd/pam-helper
	GOOS=linux GOARCH=arm64 go build $(GO_BUILD_FLAGS) -o $(BINARY_DIR)/$(ADMIN_BINARY)-linux-arm64 ./cmd/oidc-admin

## Validate project structure
validate:
	@echo "Validating project structure..."
	@test -f go.mod || (echo "go.mod not found" && exit 1)
	@test -f README.md || (echo "README.md not found" && exit 1)
	@test -f LICENSE || (echo "LICENSE not found" && exit 1)
	@test -f CHANGELOG.md || (echo "CHANGELOG.md not found" && exit 1)
	@test -f CONTRIBUTING.md || (echo "CONTRIBUTING.md not found" && exit 1)
	@test -d cmd || (echo "cmd directory not found" && exit 1)
	@test -d pkg || (echo "pkg directory not found" && exit 1)
	@echo "Project structure validation passed"

## Show help
help:
	@echo "Available targets:"
	@echo "  build           Build all binaries"
	@echo "  build-broker    Build authentication broker daemon"
	@echo "  build-pam       Build PAM module"
	@echo "  build-helper    Build PAM helper binary"
	@echo "  build-admin     Build admin CLI tool"
	@echo "  test            Run all tests"
	@echo "  test-unit       Run unit tests only"
	@echo "  test-integration Run integration tests"
	@echo "  test-e2e        Run end-to-end tests"
	@echo "  verify-linux    Run vet+test+lint for ALL packages (incl. cgo/PAM) in Docker"
	@echo "  install         Install binaries to system"
	@echo "  install-dev     Install development version"
	@echo "  clean           Clean build artifacts"
	@echo "  lint            Run linter"
	@echo "  fmt             Format code"
	@echo "  vet             Run go vet"
	@echo "  tidy            Tidy dependencies"
	@echo "  coverage        Generate coverage report"
	@echo "  security        Run security scan"
	@echo "  docker-build    Build Docker image"
	@echo "  docker-run      Run Docker container"
	@echo "  release         Create release build"
	@echo "  validate        Validate project structure"
	@echo "  help            Show this help message"