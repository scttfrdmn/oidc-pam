#!/bin/bash

set -e

# Build script for creating cross-platform releases
# This script builds binaries for multiple platforms and creates distribution packages

# Configuration
BINARY_DIR="bin"
DIST_DIR="dist"
PROJECT_NAME="oidc-pam"
VERSION=${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo "v0.1.0-alpha")}
BUILD_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
GIT_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")

# Build flags are now inline in the build commands

# Target platforms
PLATFORMS=(
    "linux/amd64"
    "linux/arm64"
    "linux/386"
    "darwin/amd64"
    "darwin/arm64"
    "windows/amd64"
)

# Binaries to build (cross-platform)
BINARIES=(
    "broker:./cmd/broker"
    "oidc-admin:./cmd/oidc-admin"
)

# Linux-only binaries (require CGO/PAM)
LINUX_BINARIES=(
    "pam-helper:./cmd/pam-helper"
)

# PAM module (Linux only)
PAM_PLATFORMS=(
    "linux/amd64"
    "linux/arm64"
    "linux/386"
)

echo "🚀 Building OIDC PAM releases"
echo "Version: ${VERSION}"
echo "Build Date: ${BUILD_DATE}"
echo "Git Commit: ${GIT_COMMIT}"
echo ""

# Clean previous builds
echo "🧹 Cleaning previous builds..."
rm -rf "${BINARY_DIR}" "${DIST_DIR}"
mkdir -p "${BINARY_DIR}" "${DIST_DIR}"

# Build regular binaries for all platforms
for platform in "${PLATFORMS[@]}"; do
    IFS='/' read -r os arch <<< "$platform"
    echo "📦 Building for ${os}/${arch}..."
    
    for binary_info in "${BINARIES[@]}"; do
        IFS=':' read -r binary_name binary_path <<< "$binary_info"
        
        output_name="${binary_name}"
        if [[ "$os" == "windows" ]]; then
            output_name="${binary_name}.exe"
        fi
        
        output_path="${BINARY_DIR}/${binary_name}-${os}-${arch}"
        if [[ "$os" == "windows" ]]; then
            output_path="${output_path}.exe"
        fi
        
        echo "  Building ${binary_name} for ${os}/${arch}..."
        GOOS="$os" GOARCH="$arch" go build -ldflags="-s -w -X main.version=${VERSION} -X main.buildDate=${BUILD_DATE} -X main.gitCommit=${GIT_COMMIT}" -trimpath -o "$output_path" "$binary_path"
        
        if [[ $? -eq 0 ]]; then
            echo "  ✅ ${binary_name} built successfully"
        else
            echo "  ❌ Failed to build ${binary_name} for ${os}/${arch}"
            exit 1
        fi
    done
    
    # Build Linux-only binaries for Linux platforms
    if [[ "$os" == "linux" ]]; then
        for binary_info in "${LINUX_BINARIES[@]}"; do
            IFS=':' read -r binary_name binary_path <<< "$binary_info"
            
            output_path="${BINARY_DIR}/${binary_name}-${os}-${arch}"
            
            echo "  Building ${binary_name} for ${os}/${arch} (Linux-only)..."
            CGO_ENABLED=1 GOOS="$os" GOARCH="$arch" go build -ldflags="-s -w -X main.version=${VERSION} -X main.buildDate=${BUILD_DATE} -X main.gitCommit=${GIT_COMMIT}" -trimpath -o "$output_path" "$binary_path"
            
            if [[ $? -eq 0 ]]; then
                echo "  ✅ ${binary_name} built successfully"
            else
                echo "  ❌ Failed to build ${binary_name} for ${os}/${arch}"
                exit 1
            fi
        done
    fi
done

# Build PAM module (Linux only, requires CGO)
echo ""
echo "🔧 Building PAM module for Linux platforms..."
for platform in "${PAM_PLATFORMS[@]}"; do
    IFS='/' read -r os arch <<< "$platform"
    echo "  Building PAM module for ${os}/${arch}..."
    
    output_path="${BINARY_DIR}/pam_oidc-${os}-${arch}.so"
    
    CGO_ENABLED=1 GOOS="$os" GOARCH="$arch" go build -buildmode=c-shared -ldflags="-s -w -X main.version=${VERSION} -X main.buildDate=${BUILD_DATE} -X main.gitCommit=${GIT_COMMIT}" -trimpath -o "$output_path" ./cmd/pam-module
    
    if [[ $? -eq 0 ]]; then
        echo "  ✅ PAM module built successfully"
    else
        echo "  ❌ Failed to build PAM module for ${os}/${arch}"
        exit 1
    fi
done

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
        if [[ "$os" == "windows" ]]; then
            src_name="${src_name}.exe"
        fi
        
        dest_name="${binary_name}"
        if [[ "$os" == "windows" ]]; then
            dest_name="${dest_name}.exe"
        fi
        
        if [[ -f "${BINARY_DIR}/${src_name}" ]]; then
            cp "${BINARY_DIR}/${src_name}" "${package_dir}/${dest_name}"
            chmod +x "${package_dir}/${dest_name}"
        fi
    done
    
    # Copy Linux-only binaries (Linux platforms only)
    if [[ "$os" == "linux" ]]; then
        for binary_info in "${LINUX_BINARIES[@]}"; do
            IFS=':' read -r binary_name binary_path <<< "$binary_info"
            
            src_name="${binary_name}-${os}-${arch}"
            dest_name="${binary_name}"
            
            if [[ -f "${BINARY_DIR}/${src_name}" ]]; then
                cp "${BINARY_DIR}/${src_name}" "${package_dir}/${dest_name}"
                chmod +x "${package_dir}/${dest_name}"
            fi
        done
    fi
    
    # Copy PAM module (Linux only)
    if [[ "$os" == "linux" ]]; then
        pam_src="${BINARY_DIR}/pam_oidc-${os}-${arch}.so"
        if [[ -f "$pam_src" ]]; then
            cp "$pam_src" "${package_dir}/pam_oidc.so"
        fi
    fi
    
    # Copy configuration files
    mkdir -p "${package_dir}/configs"
    cp -r configs/* "${package_dir}/configs/"
    
    # Copy documentation
    cp README.md "${package_dir}/"
    cp LICENSE "${package_dir}/"
    cp CHANGELOG.md "${package_dir}/"
    
    # Create installation script
    cat > "${package_dir}/install.sh" << 'EOF'
#!/bin/bash

set -e

echo "🚀 Installing OIDC PAM..."

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
cp broker /usr/local/bin/oidc-auth-broker
cp pam-helper /usr/local/bin/oidc-pam-helper
cp oidc-admin /usr/local/bin/oidc-admin
chmod +x /usr/local/bin/oidc-auth-broker
chmod +x /usr/local/bin/oidc-pam-helper
chmod +x /usr/local/bin/oidc-admin

# Install PAM module (Linux only)
if [[ "$OS" == "linux" ]] && [[ -f "pam_oidc.so" ]]; then
    echo "🔧 Installing PAM module..."
    cp pam_oidc.so /lib/security/
    chmod 644 /lib/security/pam_oidc.so
fi

# Create directories
echo "📁 Creating directories..."
mkdir -p /etc/oidc-auth
mkdir -p /var/log/oidc-auth
mkdir -p /var/run/oidc-auth

# Install configuration
if [[ ! -f /etc/oidc-auth/broker.yaml ]]; then
    echo "⚙️  Installing default configuration..."
    cp configs/examples/broker.yaml /etc/oidc-auth/
fi

# Install systemd service (Linux only)
if [[ "$OS" == "linux" ]] && [[ -f "configs/systemd/oidc-auth-broker.service" ]]; then
    echo "🔧 Installing systemd service..."
    cp configs/systemd/oidc-auth-broker.service /etc/systemd/system/
    systemctl daemon-reload
    systemctl enable oidc-auth-broker
fi

echo "✅ Installation completed successfully!"
echo ""
echo "Next steps:"
echo "1. Edit /etc/oidc-auth/broker.yaml to configure your OIDC provider"
echo "2. Start the service: systemctl start oidc-auth-broker"
echo "3. Configure PAM to use the module (see documentation)"
EOF
    
    chmod +x "${package_dir}/install.sh"
    
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
echo "🎉 Build completed successfully!"
echo ""
echo "📊 Build Summary:"
echo "  Version: ${VERSION}"
echo "  Binaries built: $(ls -1 ${BINARY_DIR}/ | wc -l)"
echo "  Packages created: $(ls -1 ${DIST_DIR}/*.tar.gz | wc -l)"
echo ""
echo "📦 Distribution packages:"
ls -la "${DIST_DIR}"/*.tar.gz

echo ""
echo "🔐 Checksums:"
cat "${DIST_DIR}/SHA256SUMS"