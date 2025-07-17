#!/bin/bash

# OIDC PAM Development Setup Script
# This script sets up a development environment for OIDC PAM

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Print functions
print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

# Check system requirements
check_requirements() {
    print_info "Checking development requirements..."
    
    # Check for Go
    if ! command -v go &> /dev/null; then
        print_error "Go is not installed. Please install Go 1.21 or later."
    fi
    
    # Check Go version
    local go_version=$(go version | awk '{print $3}' | sed 's/go//')
    local required_version="1.21"
    
    if ! printf '%s\n' "$required_version" "$go_version" | sort -V | head -n1 | grep -q "$required_version"; then
        print_error "Go version $go_version is too old. Please install Go $required_version or later."
    fi
    
    # Check for Make
    if ! command -v make &> /dev/null; then
        print_error "Make is not installed. Please install Make."
    fi
    
    # Check for Git
    if ! command -v git &> /dev/null; then
        print_error "Git is not installed. Please install Git."
    fi
    
    print_info "Development requirements check passed"
}

# Install development dependencies
install_dev_dependencies() {
    print_info "Installing development dependencies..."
    
    # Detect OS
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        if ! command -v brew &> /dev/null; then
            print_error "Homebrew is not installed. Please install Homebrew first."
        fi
        
        # Install dependencies
        brew install json-c pkg-config
        print_info "macOS dependencies installed"
        
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        # Linux
        if [[ -f /etc/os-release ]]; then
            . /etc/os-release
            OS=$ID
        else
            print_error "Cannot detect Linux distribution"
        fi
        
        case "$OS" in
            ubuntu|debian)
                sudo apt-get update
                sudo apt-get install -y \
                    build-essential \
                    libpam0g-dev \
                    libjson-c-dev \
                    pkg-config \
                    libsystemd-dev
                ;;
            rhel|centos|fedora)
                if command -v dnf &> /dev/null; then
                    sudo dnf install -y \
                        gcc \
                        make \
                        pam-devel \
                        json-c-devel \
                        pkgconfig \
                        systemd-devel
                else
                    sudo yum install -y \
                        gcc \
                        make \
                        pam-devel \
                        json-c-devel \
                        pkgconfig \
                        systemd-devel
                fi
                ;;
            *)
                print_error "Unsupported Linux distribution: $OS"
                ;;
        esac
        
        print_info "Linux dependencies installed"
    else
        print_error "Unsupported operating system: $OSTYPE"
    fi
}

# Install Go development tools
install_go_tools() {
    print_info "Installing Go development tools..."
    
    # Install linter
    if ! command -v golangci-lint &> /dev/null; then
        print_info "Installing golangci-lint..."
        go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
    fi
    
    # Install security scanner
    if ! command -v gosec &> /dev/null; then
        print_info "Installing gosec..."
        go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest
    fi
    
    # Install test coverage tools
    if ! command -v gocov &> /dev/null; then
        print_info "Installing gocov..."
        go install github.com/axw/gocov/gocov@latest
    fi
    
    print_info "Go development tools installed"
}

# Setup development environment
setup_dev_env() {
    print_info "Setting up development environment..."
    
    # Create development directories
    mkdir -p dev/configs
    mkdir -p dev/logs
    mkdir -p dev/keys
    mkdir -p dev/sockets
    
    # Create development configuration
    cat > dev/configs/broker.yaml << EOF
# Development Configuration for OIDC PAM
server:
  listen_address: "127.0.0.1:8080"
  socket_path: "dev/sockets/broker.sock"
  log_level: "debug"
  
logging:
  level: "debug"
  format: "json"
  output: "dev/logs/broker.log"
  
providers:
  # Add your OIDC provider configuration here
  example:
    name: "Example Provider"
    issuer: "https://example.com"
    client_id: "your-client-id"
    client_secret: "your-client-secret"
    scopes: ["openid", "profile", "email"]
    
# Development settings
development:
  enabled: true
  mock_provider: true
  skip_tls_verify: true
EOF
    
    # Create development scripts
    cat > dev/run-broker.sh << 'EOF'
#!/bin/bash
echo "Starting OIDC Auth Broker in development mode..."
./bin/oidc-auth-broker --config dev/configs/broker.yaml --debug
EOF
    
    cat > dev/test-auth.sh << 'EOF'
#!/bin/bash
echo "Testing authentication..."
./bin/oidc-pam-helper --config dev/configs/broker.yaml --user testuser --debug
EOF
    
    chmod +x dev/run-broker.sh
    chmod +x dev/test-auth.sh
    
    print_info "Development environment setup completed"
}

# Initialize Git hooks
setup_git_hooks() {
    print_info "Setting up Git hooks..."
    
    # Create pre-commit hook
    cat > .git/hooks/pre-commit << 'EOF'
#!/bin/bash
echo "Running pre-commit checks..."

# Run tests
if ! make test; then
    echo "Tests failed"
    exit 1
fi

# Run linter
if ! make lint; then
    echo "Linting failed"
    exit 1
fi

# Run security scan
if ! make security; then
    echo "Security scan failed"
    exit 1
fi

echo "Pre-commit checks passed"
EOF
    
    chmod +x .git/hooks/pre-commit
    
    print_info "Git hooks setup completed"
}

# Setup IDE configuration
setup_ide_config() {
    print_info "Setting up IDE configuration..."
    
    # Create VS Code configuration
    mkdir -p .vscode
    
    cat > .vscode/settings.json << 'EOF'
{
    "go.toolsManagement.checkForUpdates": "local",
    "go.useLanguageServer": true,
    "go.gopath": "",
    "go.goroot": "",
    "go.lintTool": "golangci-lint",
    "go.lintFlags": [
        "--fast"
    ],
    "go.buildOnSave": "package",
    "go.vetOnSave": "package",
    "go.formatTool": "gofmt",
    "go.formatFlags": [
        "-s"
    ],
    "go.testFlags": [
        "-v"
    ],
    "go.coverOnSave": true,
    "go.coverOnSaveMode": "package",
    "files.associations": {
        "*.c": "c",
        "*.h": "c"
    },
    "C_Cpp.default.includePath": [
        "${workspaceFolder}/**",
        "/usr/include/security",
        "/opt/homebrew/include"
    ]
}
EOF
    
    cat > .vscode/launch.json << 'EOF'
{
    "version": "0.2.0",
    "configurations": [
        {
            "name": "Launch Broker",
            "type": "go",
            "request": "launch",
            "mode": "debug",
            "program": "./cmd/broker",
            "args": [
                "--config", "dev/configs/broker.yaml",
                "--debug"
            ]
        },
        {
            "name": "Launch PAM Helper",
            "type": "go",
            "request": "launch",
            "mode": "debug",
            "program": "./cmd/pam-helper",
            "args": [
                "--config", "dev/configs/broker.yaml",
                "--user", "testuser",
                "--debug"
            ]
        }
    ]
}
EOF
    
    print_info "IDE configuration setup completed"
}

# Run initial build and tests
initial_build() {
    print_info "Running initial build and tests..."
    
    # Tidy dependencies
    make tidy
    
    # Build project
    make build
    
    # Run tests
    make test
    
    print_info "Initial build and tests completed"
}

# Print development summary
print_summary() {
    echo ""
    echo "========================================"
    echo "OIDC PAM Development Setup Complete"
    echo "========================================"
    echo ""
    echo "Development environment ready!"
    echo ""
    echo "Quick start:"
    echo "1. Configure OIDC provider in dev/configs/broker.yaml"
    echo "2. Run broker: ./dev/run-broker.sh"
    echo "3. Test authentication: ./dev/test-auth.sh"
    echo ""
    echo "Development commands:"
    echo "- Build: make build"
    echo "- Test: make test"
    echo "- Lint: make lint"
    echo "- Security scan: make security"
    echo "- Clean: make clean"
    echo ""
    echo "Development files:"
    echo "- Configuration: dev/configs/broker.yaml"
    echo "- Logs: dev/logs/"
    echo "- Scripts: dev/*.sh"
    echo ""
    echo "VS Code configuration added to .vscode/"
    echo "Git hooks configured for pre-commit checks"
    echo ""
    echo "Happy coding!"
}

# Main setup function
main() {
    print_info "Starting OIDC PAM development setup..."
    
    check_requirements
    install_dev_dependencies
    install_go_tools
    setup_dev_env
    setup_git_hooks
    setup_ide_config
    initial_build
    print_summary
    
    print_info "Development setup completed successfully!"
}

# Run main function
main "$@"