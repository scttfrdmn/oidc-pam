.PHONY: build build-pam skip-pam test install clean lint fmt vet check-cgo check-pam-producers tidy verify-linux help

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
GOOS := $(shell go env GOOS)
ifeq ($(GOOS),linux)
PAM_MODULE_TARGET := build-pam
else
PAM_MODULE_TARGET := skip-pam
endif

# The pinned golangci-lint version, single-sourced from .golangci-version so the
# CI Lint job, the verification container and a local `make lint` cannot disagree.
GOLANGCI_LINT_VERSION := $(shell tr -d '[:space:]' < .golangci-version)

# Resolve the directory this host's libpam loads modules from, into $$pamdir.
#
# `make install` used to copy the module to /lib/security, which exists on neither
# Debian/Ubuntu (/lib/<triplet>/security) nor RHEL-family (/lib64/security)
# systems (#208) -- so the copy failed, or, once an operator created the directory
# to get past that, put the module somewhere PAM never looks and every login on
# the shipped stack was refused by pam_deny.so instead.
#
# scripts/install.sh's detect_pam_dir is the one implementation of the probe;
# sourcing that script defines its functions and runs nothing. Override with
# PAM_MODULE_DIR, exactly as the installers do.
define resolve_pam_dir
pamdir="$${PAM_MODULE_DIR:-$$(bash -c 'source ./scripts/install.sh; detect_pam_dir' || true)}"; \
if [ -z "$$pamdir" ]; then \
	echo "Could not find the directory libpam loads modules from. Install your" >&2; \
	echo "distribution's PAM modules (libpam-modules on Debian/Ubuntu, pam on" >&2; \
	echo "RHEL-family), or set PAM_MODULE_DIR to the directory holding pam_unix.so." >&2; \
	exit 1; \
fi; \
echo "  PAM module directory: $$pamdir"
endef

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
	@# One script builds the module, everywhere: it applies the hardening flags,
	@# refuses to run off Linux (where the C bridge's Linux-PAM and json-c headers
	@# do not exist) and inspects the artifact it produced, because a module with
	@# no pam_sm_* symbols in it builds and exits 0 (#140, #222).
	@./scripts/build-pam-module.sh $(BINARY_DIR)/$(PAM_MODULE)

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

## Run the end-to-end harness: real sshd, real PAM stack, real broker (needs Docker)
test-e2e:
	@# Not a `go test` package. Every case is an actual SSH login against the
	@# built pam_oidc.so, which is the only way to exercise what PAM makes of the
	@# module's return codes. See test/e2e/README.md.
	./test/e2e/run-tests.sh

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
		sh -c './scripts/check-cgo-quarantine.sh \
			&& ./scripts/check-pam-module-producers.sh \
			&& go vet ./... \
			&& go test -race ./... \
			&& golangci-lint run --timeout=5m ./... \
			&& echo "Building and verifying the PAM module..." \
			&& ./scripts/build-pam-module.sh /tmp/pam_oidc.so'

## Install binaries to system locations
install: build
	@echo "Installing binaries..."
	@set -e; $(resolve_pam_dir); \
	sudo install -m 0644 $(BINARY_DIR)/$(PAM_MODULE) "$$pamdir/$(PAM_MODULE)"
	sudo install -m 0755 $(BINARY_DIR)/$(BROKER_BINARY) /usr/local/bin/$(BROKER_BINARY)
	sudo install -m 0755 $(BINARY_DIR)/$(HELPER_BINARY) /usr/local/bin/$(HELPER_BINARY)
	sudo install -m 0755 $(BINARY_DIR)/$(ADMIN_BINARY) /usr/local/bin/$(ADMIN_BINARY)
	sudo cp configs/systemd/oidc-auth-broker.service /etc/systemd/system/
	sudo systemctl daemon-reload
	sudo systemctl enable oidc-auth-broker

## Install development version
install-dev: build
	@echo "Installing development version..."
	@set -e; $(resolve_pam_dir); \
	sudo install -m 0644 $(BINARY_DIR)/$(PAM_MODULE) "$$pamdir/$(PAM_MODULE)"
	sudo install -m 0755 $(BINARY_DIR)/$(BROKER_BINARY) /usr/local/bin/$(BROKER_BINARY)
	sudo install -m 0755 $(BINARY_DIR)/$(HELPER_BINARY) /usr/local/bin/$(HELPER_BINARY)
	sudo install -m 0755 $(BINARY_DIR)/$(ADMIN_BINARY) /usr/local/bin/$(ADMIN_BINARY)
	sudo install -d -m 0750 -o root -g root /etc/oidc-auth
	# 0600 root:root: this file holds the token encryption key and every client
	# secret, and the broker refuses to start if anyone else can read it (#209).
	sudo install -m 0600 -o root -g root configs/examples/broker.yaml /etc/oidc-auth/broker.yaml
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

## Check that cgo stays confined to cmd/pam-module (works on any OS)
check-cgo:
	@./scripts/check-cgo-quarantine.sh

## Check nothing but build-pam-module.sh compiles the module (works on any OS)
check-pam-producers:
	@./scripts/check-pam-module-producers.sh

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
##
## The broker, helper and admin CLI cross-compile from anywhere. The PAM module
## does not: it is C, so it needs a compiler that targets the output architecture
## and that architecture's PAM and json-c headers. Building it for the other
## architecture here needs CC set to a cross-toolchain; build-pam-module.sh
## refuses rather than writing a host-architecture module under a name that claims
## otherwise. The released modules are built on a runner of each architecture —
## see the build matrix in .github/workflows/release.yml, which is the release
## path this target predates.
release: clean
	@echo "Creating release build..."
	@mkdir -p $(BINARY_DIR)
	GOOS=linux GOARCH=amd64 go build $(GO_BUILD_FLAGS) -o $(BINARY_DIR)/$(BROKER_BINARY)-linux-amd64 ./cmd/broker
	./scripts/build-pam-module.sh $(BINARY_DIR)/$(PAM_MODULE)-linux-amd64 amd64
	GOOS=linux GOARCH=amd64 go build $(GO_BUILD_FLAGS) -o $(BINARY_DIR)/$(HELPER_BINARY)-linux-amd64 ./cmd/pam-helper
	GOOS=linux GOARCH=amd64 go build $(GO_BUILD_FLAGS) -o $(BINARY_DIR)/$(ADMIN_BINARY)-linux-amd64 ./cmd/oidc-admin
	GOOS=linux GOARCH=arm64 go build $(GO_BUILD_FLAGS) -o $(BINARY_DIR)/$(BROKER_BINARY)-linux-arm64 ./cmd/broker
	./scripts/build-pam-module.sh $(BINARY_DIR)/$(PAM_MODULE)-linux-arm64 arm64
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
	@echo "  test-e2e        Run the end-to-end SSH/PAM harness in Docker"
	@echo "  verify-linux    Run vet+test+lint for ALL packages (incl. cgo/PAM) in Docker"
	@echo "  install         Install binaries to system"
	@echo "  install-dev     Install development version"
	@echo "  clean           Clean build artifacts"
	@echo "  lint            Run linter"
	@echo "  fmt             Format code"
	@echo "  vet             Run go vet"
	@echo "  check-cgo       Check cgo is confined to cmd/pam-module"
	@echo "  check-pam-producers  Check one script is the only producer of the PAM module"
	@echo "  tidy            Tidy dependencies"
	@echo "  coverage        Generate coverage report"
	@echo "  security        Run security scan"
	@echo "  docker-build    Build Docker image"
	@echo "  docker-run      Run Docker container"
	@echo "  release         Create release build"
	@echo "  validate        Validate project structure"
	@echo "  help            Show this help message"