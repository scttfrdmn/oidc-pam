#!/bin/bash

set -e

# Simplified build script for alpha release
# This builds what we can locally without complex cross-compilation

# Configuration
BINARY_DIR="bin"
DIST_DIR="dist"
PROJECT_NAME="oidc-pam"
VERSION=${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo "v0.1.0-alpha")}
BUILD_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
GIT_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")

# Platforms we can build easily
PLATFORMS=(
    "linux/amd64"
    "linux/arm64"
    "darwin/amd64"
    "darwin/arm64"
)

# Core binaries (no CGO dependencies)
BINARIES=(
    "broker:./cmd/broker"
    "oidc-admin:./cmd/oidc-admin"
)

echo "🚀 Building OIDC PAM Alpha Release (Simplified)"
echo "Version: ${VERSION}"
echo "Build Date: ${BUILD_DATE}"
echo "Git Commit: ${GIT_COMMIT}"
echo ""

# Clean previous builds
echo "🧹 Cleaning previous builds..."
rm -rf "${BINARY_DIR}" "${DIST_DIR}"
mkdir -p "${BINARY_DIR}" "${DIST_DIR}"

# Build core binaries for supported platforms
for platform in "${PLATFORMS[@]}"; do
    IFS='/' read -r os arch <<< "$platform"
    echo "📦 Building for ${os}/${arch}..."
    
    for binary_info in "${BINARIES[@]}"; do
        IFS=':' read -r binary_name binary_path <<< "$binary_info"
        
        output_path="${BINARY_DIR}/${binary_name}-${os}-${arch}"
        
        echo "  Building ${binary_name} for ${os}/${arch}..."
        GOOS="$os" GOARCH="$arch" go build -ldflags="-s -w -X main.version=${VERSION} -X main.buildDate=${BUILD_DATE} -X main.gitCommit=${GIT_COMMIT}" -trimpath -o "$output_path" "$binary_path"
        
        if [[ $? -eq 0 ]]; then
            echo "  ✅ ${binary_name} built successfully"
        else
            echo "  ❌ Failed to build ${binary_name} for ${os}/${arch}"
            exit 1
        fi
    done
done

# Build native PAM helper (for current platform only)
echo ""
echo "🔧 Building PAM helper for current platform..."
if [[ "$(uname -s)" == "Darwin" ]]; then
    echo "  Skipping PAM helper on macOS (requires Linux)"
else
    CGO_ENABLED=1 go build -ldflags="-s -w -X main.version=${VERSION} -X main.buildDate=${BUILD_DATE} -X main.gitCommit=${GIT_COMMIT}" -trimpath -o "${BINARY_DIR}/pam-helper-native" ./cmd/pam-helper
    
    if [[ $? -eq 0 ]]; then
        echo "  ✅ PAM helper built successfully"
    else
        echo "  ❌ Failed to build PAM helper"
    fi
fi

# Build native PAM module (for current platform only)
echo ""
echo "🔧 Building PAM module for current platform..."
if [[ "$(uname -s)" == "Darwin" ]]; then
    echo "  Skipping PAM module on macOS (requires Linux)"
else
    CGO_ENABLED=1 go build -buildmode=c-shared -ldflags="-s -w -X main.version=${VERSION} -X main.buildDate=${BUILD_DATE} -X main.gitCommit=${GIT_COMMIT}" -trimpath -o "${BINARY_DIR}/pam_oidc-native.so" ./cmd/pam-module
    
    if [[ $? -eq 0 ]]; then
        echo "  ✅ PAM module built successfully"
    else
        echo "  ❌ Failed to build PAM module"
    fi
fi

# Create distribution packages
echo ""
echo "📦 Creating distribution packages..."

for platform in "${PLATFORMS[@]}"; do
    IFS='/' read -r os arch <<< "$platform"
    package_name="${PROJECT_NAME}-${VERSION}-${os}-${arch}"
    package_dir="${DIST_DIR}/${package_name}"
    
    echo "  Creating package for ${os}/${arch}..."
    mkdir -p "$package_dir"
    
    # Copy binaries
    for binary_info in "${BINARIES[@]}"; do
        IFS=':' read -r binary_name binary_path <<< "$binary_info"
        
        src_name="${binary_name}-${os}-${arch}"
        dest_name="${binary_name}"
        
        if [[ -f "${BINARY_DIR}/${src_name}" ]]; then
            cp "${BINARY_DIR}/${src_name}" "${package_dir}/${dest_name}"
            chmod +x "${package_dir}/${dest_name}"
        fi
    done
    
    # Copy native PAM components (if available and this is a Linux package)
    if [[ "$os" == "linux" ]]; then
        if [[ -f "${BINARY_DIR}/pam-helper-native" ]]; then
            cp "${BINARY_DIR}/pam-helper-native" "${package_dir}/pam-helper"
            chmod +x "${package_dir}/pam-helper"
        fi
        
        if [[ -f "${BINARY_DIR}/pam_oidc-native.so" ]]; then
            cp "${BINARY_DIR}/pam_oidc-native.so" "${package_dir}/pam_oidc.so"
        fi
    fi
    
    # Copy configuration files
    mkdir -p "${package_dir}/configs"
    cp -r configs/* "${package_dir}/configs/" 2>/dev/null || true
    
    # Copy documentation
    cp README.md "${package_dir}/" 2>/dev/null || echo "# OIDC PAM Alpha Release" > "${package_dir}/README.md"
    cp LICENSE "${package_dir}/" 2>/dev/null || echo "See project repository for license information" > "${package_dir}/LICENSE"
    cp CHANGELOG.md "${package_dir}/" 2>/dev/null || echo "# Changelog\n\nSee project repository for changelog information" > "${package_dir}/CHANGELOG.md"
    
    # Create installation script
    cat > "${package_dir}/install.sh" << 'EOF'
#!/bin/bash

set -e

echo "🚀 Installing OIDC PAM Alpha Release..."

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo "❌ This script must be run as root (use sudo)"
    exit 1
fi

# Detect OS and architecture
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case $ARCH in
    x86_64) ARCH="amd64" ;;
    aarch64) ARCH="arm64" ;;
    armv7l) ARCH="arm" ;;
    i386) ARCH="386" ;;
esac

echo "Detected: ${OS}/${ARCH}"

# Install binaries
echo "📦 Installing binaries..."
if [[ -f "broker" ]]; then
    cp broker /usr/local/bin/oidc-auth-broker
    chmod +x /usr/local/bin/oidc-auth-broker
    echo "  ✅ Broker installed"
fi

if [[ -f "pam-helper" ]]; then
    cp pam-helper /usr/local/bin/oidc-pam-helper
    chmod +x /usr/local/bin/oidc-pam-helper
    echo "  ✅ PAM helper installed"
fi

if [[ -f "oidc-admin" ]]; then
    cp oidc-admin /usr/local/bin/oidc-admin
    chmod +x /usr/local/bin/oidc-admin
    echo "  ✅ Admin tool installed"
fi

# Install PAM module (Linux only)
if [[ "$OS" == "linux" ]] && [[ -f "pam_oidc.so" ]]; then
    echo "🔧 Installing PAM module..."
    cp pam_oidc.so /lib/security/
    chmod 644 /lib/security/pam_oidc.so
    echo "  ✅ PAM module installed"
fi

# Create directories
echo "📁 Creating directories..."
mkdir -p /etc/oidc-auth
mkdir -p /var/log/oidc-auth
mkdir -p /var/run/oidc-auth

# Install configuration
if [[ -f "configs/examples/broker.yaml" ]] && [[ ! -f /etc/oidc-auth/broker.yaml ]]; then
    echo "⚙️  Installing default configuration..."
    cp configs/examples/broker.yaml /etc/oidc-auth/
    echo "  ✅ Configuration installed"
fi

# Install systemd service (Linux only)
if [[ "$OS" == "linux" ]] && [[ -f "configs/systemd/oidc-auth-broker.service" ]]; then
    echo "🔧 Installing systemd service..."
    cp configs/systemd/oidc-auth-broker.service /etc/systemd/system/
    systemctl daemon-reload
    systemctl enable oidc-auth-broker
    echo "  ✅ Systemd service installed"
fi

echo "✅ Installation completed successfully!"
echo ""
echo "⚠️  ALPHA RELEASE NOTICE:"
echo "This is an alpha release for testing purposes only."
echo "Do not use in production environments."
echo ""
echo "📋 Next steps:"
echo "1. Edit /etc/oidc-auth/broker.yaml to configure your OIDC provider"
echo "2. Start the service: systemctl start oidc-auth-broker"
echo "3. Configure PAM to use the module (see documentation)"
echo "4. Test the authentication flow"
echo ""
echo "📚 Documentation: https://github.com/scttfrdmn/oidc-pam"
echo "🐛 Report issues: https://github.com/scttfrdmn/oidc-pam/issues"
EOF
    
    chmod +x "${package_dir}/install.sh"
    
    # Create alpha release notes
    cat > "${package_dir}/ALPHA-RELEASE-NOTES.md" << EOF
# OIDC PAM Alpha Release ${VERSION}

**⚠️ ALPHA RELEASE - FOR TESTING ONLY**

This is an alpha release of the OIDC PAM authentication system. It is intended for testing and development purposes only. **Do not use in production environments.**

## What's Included

- **oidc-auth-broker**: Main authentication broker daemon
- **oidc-admin**: Administrative CLI tool
- **pam-helper**: PAM integration helper (Linux only)
- **pam_oidc.so**: PAM module (Linux only)
- Configuration examples
- Installation script

## Installation

1. Extract the package:
   \`\`\`bash
   tar -xzf ${package_name}.tar.gz
   cd ${package_name}
   \`\`\`

2. Run the installation script:
   \`\`\`bash
   sudo ./install.sh
   \`\`\`

## Quick Start

1. Edit the configuration:
   \`\`\`bash
   sudo nano /etc/oidc-auth/broker.yaml
   \`\`\`

2. Configure your OIDC provider settings

3. Start the broker:
   \`\`\`bash
   sudo systemctl start oidc-auth-broker
   \`\`\`

4. Check the status:
   \`\`\`bash
   sudo systemctl status oidc-auth-broker
   \`\`\`

## Known Limitations

- Alpha quality - expect bugs and missing features
- Limited testing on different platforms
- Documentation is incomplete
- No automatic updates
- Limited error handling

## Support

- Documentation: https://github.com/scttfrdmn/oidc-pam
- Issues: https://github.com/scttfrdmn/oidc-pam/issues
- Discussions: https://github.com/scttfrdmn/oidc-pam/discussions

## Version Information

- Version: ${VERSION}
- Build Date: ${BUILD_DATE}
- Git Commit: ${GIT_COMMIT}
EOF
    
    # Create tarball
    cd "$DIST_DIR"
    tar -czf "${package_name}.tar.gz" "$package_name"
    cd ..
    
    echo "  ✅ Package created: ${package_name}.tar.gz"
done

# Create checksums
echo ""
echo "🔐 Creating checksums..."
cd "$DIST_DIR"
sha256sum *.tar.gz > SHA256SUMS
cd ..

echo ""
echo "🎉 Alpha release build completed successfully!"
echo ""
echo "📊 Build Summary:"
echo "  Version: ${VERSION}"
echo "  Platforms: ${#PLATFORMS[@]}"
echo "  Binaries built: $(ls -1 ${BINARY_DIR}/ | wc -l)"
echo "  Packages created: $(ls -1 ${DIST_DIR}/*.tar.gz | wc -l)"
echo ""
echo "📦 Distribution packages:"
ls -la "${DIST_DIR}"/*.tar.gz

echo ""
echo "🔐 Checksums:"
cat "${DIST_DIR}/SHA256SUMS"

echo ""
echo "📋 Next steps for full cross-platform builds:"
echo "1. Set up CI/CD pipeline with Linux build environment"
echo "2. Use Docker containers for cross-compilation"
echo "3. Build .deb and .rpm packages"
echo "4. Set up automated testing"
echo ""
echo "🚀 Ready for alpha testing!"