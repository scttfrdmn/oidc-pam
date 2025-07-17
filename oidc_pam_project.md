# Universal OIDC PAM Authentication System

## Project Overview

A comprehensive Linux authentication solution using OpenID Connect (OIDC) that works across console, SSH, and graphical logins with modern MFA support including Passkeys, YubiKey, and Duo.

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   PAM Module    │    │ Auth Broker     │    │ OIDC Provider   │
│   (Go + CGO)    │───▶│   Daemon        │───▶│  (Okta/Azure)   │
│                 │    │   (Go)          │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         │                       │                       │
    ┌─────────┐            ┌─────────────┐         ┌──────────┐
    │ Console │            │ Token Cache │         │   MFA    │
    │   SSH   │            │ QR Display  │         │ Passkeys │
    │   GUI   │            │ Config Mgmt │         │ YubiKey  │
    └─────────┘            └─────────────┘         └──────────┘
```

## Project Structure

```
oidc-pam/
├── cmd/
│   ├── broker/                 # Authentication broker daemon
│   │   └── main.go
│   ├── pam-helper/            # PAM helper binary
│   │   └── main.go
│   └── oidc-admin/            # Administrative CLI tool
│       └── main.go
├── pkg/
│   ├── auth/                  # Core authentication logic
│   │   ├── broker.go
│   │   ├── device_flow.go
│   │   ├── token_manager.go
│   │   └── oidc_client.go
│   ├── config/                # Configuration management
│   │   ├── config.go
│   │   ├── cloud_metadata.go
│   │   └── validation.go
│   ├── display/               # User interface components
│   │   ├── console.go
│   │   ├── qr_code.go
│   │   ├── notifications.go
│   │   └── terminal.go
│   ├── pam/                   # PAM integration
│   │   ├── module.go
│   │   ├── cgo_bridge.c
│   │   ├── cgo_bridge.h
│   │   └── types.go
│   ├── security/              # Security utilities
│   │   ├── token_crypto.go
│   │   ├── secure_storage.go
│   │   └── audit.go
│   └── cloud/                 # Cloud provider integrations
│       ├── aws.go
│       ├── azure.go
│       └── gcp.go
├── internal/
│   ├── ipc/                   # Inter-process communication
│   │   ├── unix_socket.go
│   │   └── protocol.go
│   └── utils/
│       ├── logging.go
│       └── helpers.go
├── configs/
│   ├── broker.yaml.example
│   ├── pam.conf.example
│   └── systemd/
│       └── oidc-auth-broker.service
├── scripts/
│   ├── install.sh
│   ├── build.sh
│   ├── test-setup.sh
│   └── cloud-init/
│       ├── aws-userdata.sh
│       ├── azure-custom-data.sh
│       └── gcp-startup-script.sh
├── test/
│   ├── integration/
│   │   ├── docker-compose.yml
│   │   ├── test-suite.go
│   │   └── mock-oidc-server.go
│   └── unit/
│       └── *_test.go files
├── docs/
│   ├── deployment/
│   │   ├── cloud-setup.md
│   │   ├── on-premises.md
│   │   └── security-considerations.md
│   ├── configuration/
│   │   ├── oidc-providers.md
│   │   ├── mfa-setup.md
│   │   └── troubleshooting.md
│   └── development/
│       ├── contributing.md
│       └── architecture.md
├── Makefile
├── go.mod
├── go.sum
├── README.md
└── LICENSE
```

## Technology Stack

### Core Technologies
- **Go 1.21+**: Main implementation language
- **CGO**: PAM module interface
- **libpam**: PAM development libraries
- **systemd**: Service management

### Key Dependencies
```go
// go.mod dependencies
require (
    github.com/coreos/go-oidc/v3 v3.7.0
    github.com/golang-jwt/jwt/v5 v5.0.0
    github.com/skip2/go-qrcode v0.0.0-20200617195104-da1b6568686e
    github.com/spf13/cobra v1.7.0
    github.com/spf13/viper v1.16.0
    github.com/gorilla/websocket v1.5.0
    github.com/rs/zerolog v1.30.0
    github.com/stretchr/testify v1.8.4
    golang.org/x/crypto v0.13.0
    golang.org/x/oauth2 v0.12.0
    gopkg.in/yaml.v3 v3.0.1
)
```

## Development Environment Setup

### Prerequisites
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install -y \
    golang-1.21 \
    libpam0g-dev \
    libssl-dev \
    build-essential \
    git \
    make \
    pkg-config

# RHEL/CentOS/Fedora
sudo dnf install -y \
    golang \
    pam-devel \
    openssl-devel \
    gcc \
    make \
    git \
    pkg-config
```

### Initial Setup
```bash
# Clone and initialize
git clone <your-repo-url> oidc-pam
cd oidc-pam

# Initialize Go module
go mod init github.com/yourusername/oidc-pam

# Install dependencies
go mod tidy

# Build project
make build

# Run tests
make test

# Install development version
sudo make install-dev
```

## Key Components

### 1. Authentication Broker (`cmd/broker/main.go`)
```go
// Main daemon that handles OIDC flows
// - Device flow orchestration
// - Token management and caching
// - Unix socket server for PAM communication
// - Configuration hot-reloading
// - Audit logging
```

### 2. PAM Module (`pkg/pam/`)
```go
// CGO-based PAM module
// - Standard PAM interface implementation
// - Communication with broker via Unix socket
// - Different UX for console/SSH/GUI
// - Graceful fallback handling
```

### 3. Device Flow Implementation (`pkg/auth/device_flow.go`)
```go
// OAuth2 Device Authorization Grant
// - Provider-agnostic implementation
// - QR code generation and display
// - Polling for authorization completion
// - Token exchange and validation
```

### 4. Display Layer (`pkg/display/`)
```go
// Adaptive user interface
// - ASCII QR codes for console
// - Terminal capability detection
// - Desktop notifications for GUI
// - Mobile-optimized instruction pages
```

## Configuration System

### Broker Configuration (`configs/broker.yaml.example`)
```yaml
server:
  socket_path: "/var/run/oidc-auth/broker.sock"
  log_level: "info"
  audit_log: "/var/log/oidc-auth/audit.log"

oidc:
  providers:
    - name: "corporate"
      issuer: "https://login.company.com"
      client_id: "linux-pam-client"
      scopes: ["openid", "email", "groups"]
      device_endpoint: "https://login.company.com/oauth2/device"
      token_endpoint: "https://login.company.com/oauth2/token"
      
authentication:
  token_lifetime: "8h"
  refresh_threshold: "1h"
  max_concurrent_sessions: 10
  require_groups: ["linux-users", "developers"]
  
security:
  token_encryption_key: "/etc/oidc-auth/token.key"
  audit_enabled: true
  secure_token_storage: true

cloud:
  auto_discovery: true
  metadata_sources: ["aws", "azure", "gcp"]
  
display:
  qr_code_size: "small"
  terminal_colors: true
  notification_timeout: "300s"
```

### PAM Configuration
```bash
# /etc/pam.d/sshd
auth required pam_oidc.so config=/etc/oidc-auth/pam.conf
account required pam_oidc.so
session optional pam_oidc.so

# /etc/pam.d/login (console)
auth required pam_oidc.so config=/etc/oidc-auth/pam.conf
account required pam_oidc.so
session optional pam_oidc.so

# /etc/pam.d/gdm-password (GUI)
auth required pam_oidc.so config=/etc/oidc-auth/pam.conf
account required pam_oidc.so
session optional pam_oidc.so
```

## Build System

### Makefile
```makefile
.PHONY: build test install clean

BINARY_DIR := bin
PAM_MODULE := pam_oidc.so
BROKER_BINARY := oidc-auth-broker
HELPER_BINARY := oidc-pam-helper

build: build-broker build-pam build-helper

build-broker:
	go build -o $(BINARY_DIR)/$(BROKER_BINARY) ./cmd/broker

build-pam:
	go build -buildmode=c-shared -o $(BINARY_DIR)/$(PAM_MODULE) ./pkg/pam

build-helper:
	go build -o $(BINARY_DIR)/$(HELPER_BINARY) ./cmd/pam-helper

test:
	go test -v ./...

install: build
	sudo cp $(BINARY_DIR)/$(PAM_MODULE) /lib/security/
	sudo cp $(BINARY_DIR)/$(BROKER_BINARY) /usr/local/bin/
	sudo cp $(BINARY_DIR)/$(HELPER_BINARY) /usr/local/bin/
	sudo cp configs/systemd/oidc-auth-broker.service /etc/systemd/system/
	sudo systemctl daemon-reload
	sudo systemctl enable oidc-auth-broker

clean:
	rm -rf $(BINARY_DIR)
```

## Testing Strategy

### Integration Tests
```bash
# Docker-based test environment
cd test/integration
docker-compose up -d

# Run test suite
go test -v ./test/integration/...

# Test specific scenarios
./scripts/test-console-login.sh
./scripts/test-ssh-login.sh
./scripts/test-gui-login.sh
```

### Unit Tests
```bash
# Run all unit tests
go test -v ./...

# Test with race detection
go test -race -v ./...

# Generate coverage report
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

## Deployment

### Cloud Deployment
```bash
# AWS
./scripts/cloud-init/aws-userdata.sh

# Azure
./scripts/cloud-init/azure-custom-data.sh

# GCP
./scripts/cloud-init/gcp-startup-script.sh
```

### On-Premises
```bash
# Standard installation
sudo ./scripts/install.sh

# Custom configuration
sudo ./scripts/install.sh --config /path/to/custom/config.yaml
```

## Security Considerations

### Token Security
- Tokens encrypted at rest using AES-256
- Secure memory handling for sensitive data
- Automatic token rotation and cleanup
- HSM integration for key management

### Network Security
- Unix domain sockets for local IPC
- TLS for all external communications
- Certificate pinning for OIDC providers
- Network segmentation support

### Audit and Compliance
- Comprehensive audit logging
- SIEM integration capabilities
- SOC 2 Type II compliance ready
- GDPR privacy controls

## Development Workflow

### Getting Started
1. Set up development environment
2. Run `make build` to build all components
3. Use `make install-dev` for development installation
4. Test with mock OIDC provider: `cd test && docker-compose up`
5. Run integration tests: `make test-integration`

### Contributing
1. Fork the repository
2. Create feature branch: `git checkout -b feature/amazing-feature`
3. Run tests: `make test`
4. Submit pull request

### Release Process
1. Update version in `go.mod`
2. Tag release: `git tag v1.0.0`
3. Build release artifacts: `make release`
4. Publish to GitHub releases
5. Update documentation

## Monitoring and Operations

### Health Checks
- Broker daemon health endpoint
- PAM module status monitoring
- OIDC provider connectivity checks
- Token cache statistics

### Logging
- Structured logging with zerolog
- Configurable log levels
- Audit trail for all authentication events
- Integration with system logging

### Metrics
- Authentication success/failure rates
- Token cache hit rates
- Response time metrics
- Provider availability statistics

## Next Steps

1. **Phase 1**: Implement core broker and basic PAM module
2. **Phase 2**: Add device flow and QR code display
3. **Phase 3**: Implement cloud metadata integration
4. **Phase 4**: Add advanced MFA and Passkey support
5. **Phase 5**: Enterprise features and compliance

## Resources

- [OIDC Specification](https://openid.net/connect/)
- [OAuth2 Device Flow RFC](https://tools.ietf.org/html/rfc8628)
- [PAM Documentation](http://www.linux-pam.org/Linux-PAM-html/)
- [Go CGO Documentation](https://golang.org/cmd/cgo/)
