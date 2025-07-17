#!/bin/bash

# OIDC PAM Installation Script
# This script installs the OIDC PAM authentication system

set -e

# Configuration
INSTALL_DIR="/usr/local/bin"
PAM_DIR="/lib/security"
CONFIG_DIR="/etc/oidc-auth"
RUN_DIR="/var/run/oidc-auth"
LOG_DIR="/var/log/oidc-auth"
SYSTEMD_DIR="/etc/systemd/system"

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

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root"
    fi
}

# Check system requirements
check_requirements() {
    print_info "Checking system requirements..."
    
    # Check for required commands
    local required_commands=("systemctl" "id" "getent")
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            print_error "Required command '$cmd' not found"
        fi
    done
    
    # Check for PAM
    if [[ ! -d "/etc/pam.d" ]]; then
        print_error "PAM configuration directory not found"
    fi
    
    # Check for systemd
    if [[ ! -d "/etc/systemd/system" ]]; then
        print_error "systemd not found"
    fi
    
    print_info "System requirements check passed"
}

# Install system dependencies
install_dependencies() {
    print_info "Installing system dependencies..."
    
    # Detect OS
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$ID
    else
        print_error "Cannot detect operating system"
    fi
    
    case "$OS" in
        ubuntu|debian)
            apt-get update
            apt-get install -y libpam0g-dev libjson-c-dev pkg-config libsystemd-dev
            ;;
        rhel|centos|fedora)
            if command -v dnf &> /dev/null; then
                dnf install -y pam-devel json-c-devel pkgconfig systemd-devel
            else
                yum install -y pam-devel json-c-devel pkgconfig systemd-devel
            fi
            ;;
        *)
            print_warn "Unsupported OS: $OS. Please install dependencies manually."
            ;;
    esac
    
    print_info "Dependencies installed"
}

# Create required directories
create_directories() {
    print_info "Creating required directories..."
    
    # Create directories with proper permissions
    mkdir -p "$CONFIG_DIR"
    chmod 755 "$CONFIG_DIR"
    
    mkdir -p "$RUN_DIR"
    chmod 755 "$RUN_DIR"
    
    mkdir -p "$LOG_DIR"
    chmod 755 "$LOG_DIR"
    
    print_info "Directories created"
}

# Create oidc-auth user
create_user() {
    print_info "Creating oidc-auth user..."
    
    if ! id "oidc-auth" &>/dev/null; then
        useradd -r -s /bin/false -d /var/lib/oidc-auth -c "OIDC Auth Service" oidc-auth
        print_info "User oidc-auth created"
    else
        print_info "User oidc-auth already exists"
    fi
    
    # Set ownership
    chown -R oidc-auth:oidc-auth "$RUN_DIR"
    chown -R oidc-auth:oidc-auth "$LOG_DIR"
}

# Install binaries
install_binaries() {
    print_info "Installing binaries..."
    
    # Check if binaries exist
    if [[ ! -f "bin/oidc-auth-broker" ]]; then
        print_error "Binary bin/oidc-auth-broker not found. Please run 'make build' first."
    fi
    
    if [[ ! -f "bin/oidc-pam-helper" ]]; then
        print_error "Binary bin/oidc-pam-helper not found. Please run 'make build' first."
    fi
    
    if [[ ! -f "bin/pam_oidc.so" ]]; then
        print_error "PAM module bin/pam_oidc.so not found. Please run 'make build' first."
    fi
    
    # Install binaries
    cp bin/oidc-auth-broker "$INSTALL_DIR/"
    cp bin/oidc-pam-helper "$INSTALL_DIR/"
    cp bin/pam_oidc.so "$PAM_DIR/"
    
    # Set permissions
    chmod 755 "$INSTALL_DIR/oidc-auth-broker"
    chmod 755 "$INSTALL_DIR/oidc-pam-helper"
    chmod 644 "$PAM_DIR/pam_oidc.so"
    
    print_info "Binaries installed"
}

# Install configuration files
install_config() {
    print_info "Installing configuration files..."
    
    # Install broker configuration
    if [[ -f "configs/examples/broker.yaml" ]]; then
        cp configs/examples/broker.yaml "$CONFIG_DIR/"
        chmod 644 "$CONFIG_DIR/broker.yaml"
        print_info "Broker configuration installed"
    else
        print_warn "Broker configuration not found, skipping"
    fi
    
    # Install systemd service
    if [[ -f "configs/systemd/oidc-auth-broker.service" ]]; then
        cp configs/systemd/oidc-auth-broker.service "$SYSTEMD_DIR/"
        chmod 644 "$SYSTEMD_DIR/oidc-auth-broker.service"
        print_info "Systemd service installed"
    else
        print_warn "Systemd service file not found, skipping"
    fi
}

# Configure PAM
configure_pam() {
    print_info "Configuring PAM..."
    
    # Backup existing PAM configuration
    if [[ -f "/etc/pam.d/sshd" ]]; then
        cp "/etc/pam.d/sshd" "/etc/pam.d/sshd.backup.$(date +%Y%m%d-%H%M%S)"
    fi
    
    # Check if OIDC PAM is already configured
    if grep -q "pam_oidc.so" /etc/pam.d/sshd 2>/dev/null; then
        print_info "OIDC PAM already configured in SSH"
    else
        # Add OIDC PAM to SSH configuration
        sed -i '1i# OIDC PAM Authentication' /etc/pam.d/sshd
        sed -i '2i@include common-auth' /etc/pam.d/sshd
        sed -i '3iauth sufficient pam_oidc.so' /etc/pam.d/sshd
        print_info "OIDC PAM configured for SSH"
    fi
    
    print_warn "PAM configuration updated. Please review /etc/pam.d/sshd"
}

# Enable and start services
enable_services() {
    print_info "Enabling services..."
    
    # Reload systemd
    systemctl daemon-reload
    
    # Enable but don't start the service (requires configuration)
    systemctl enable oidc-auth-broker.service
    
    print_info "Services enabled"
    print_warn "Service not started. Please configure /etc/oidc-auth/broker.yaml first"
}

# Post-installation tasks
post_install() {
    print_info "Running post-installation tasks..."
    
    # Create log file
    touch "$LOG_DIR/broker.log"
    chown oidc-auth:oidc-auth "$LOG_DIR/broker.log"
    chmod 644 "$LOG_DIR/broker.log"
    
    # Create socket directory
    mkdir -p "$RUN_DIR"
    chown oidc-auth:oidc-auth "$RUN_DIR"
    chmod 755 "$RUN_DIR"
    
    print_info "Post-installation tasks completed"
}

# Print installation summary
print_summary() {
    echo ""
    echo "========================================"
    echo "OIDC PAM Installation Complete"
    echo "========================================"
    echo ""
    echo "Next steps:"
    echo "1. Configure OIDC provider in $CONFIG_DIR/broker.yaml"
    echo "2. Start the service: systemctl start oidc-auth-broker"
    echo "3. Check logs: journalctl -u oidc-auth-broker -f"
    echo "4. Test authentication: oidc-pam-helper --user testuser"
    echo ""
    echo "Configuration files:"
    echo "- Broker: $CONFIG_DIR/broker.yaml"
    echo "- PAM: /etc/pam.d/sshd"
    echo "- Service: $SYSTEMD_DIR/oidc-auth-broker.service"
    echo ""
    echo "Log files:"
    echo "- Broker: $LOG_DIR/broker.log"
    echo "- System: journalctl -u oidc-auth-broker"
    echo ""
    echo "For more information, see README.md and REQUIREMENTS.md"
}

# Main installation function
main() {
    print_info "Starting OIDC PAM installation..."
    
    check_root
    check_requirements
    install_dependencies
    create_directories
    create_user
    install_binaries
    install_config
    configure_pam
    enable_services
    post_install
    print_summary
    
    print_info "Installation completed successfully!"
}

# Run main function
main "$@"