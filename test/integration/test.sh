#!/bin/bash

set -e

echo "🧪 Testing integration setup..."

# Test 1: Check if configuration is valid
echo "✅ Test 1: Configuration validation"
if [ -f "test/config/integration-test.yaml" ]; then
    echo "   ✓ Configuration file exists"
else
    echo "   ✗ Configuration file missing"
    exit 1
fi

# Test 2: Check if Keycloak realm config is valid
echo "✅ Test 2: Keycloak realm configuration"
if [ -f "test/keycloak/import/test-realm.json" ]; then
    echo "   ✓ Keycloak realm configuration exists"
    # Validate JSON
    if jq empty test/keycloak/import/test-realm.json 2>/dev/null; then
        echo "   ✓ Keycloak realm configuration is valid JSON"
    else
        echo "   ✗ Keycloak realm configuration is invalid JSON"
        exit 1
    fi
else
    echo "   ✗ Keycloak realm configuration missing"
    exit 1
fi

# Test 3: Check if integration test binary builds
echo "✅ Test 3: Integration test binary"
if go build -tags integration -o integration-test-tmp ./test/integration/main.go; then
    echo "   ✓ Integration test binary builds successfully"
    rm -f integration-test-tmp
else
    echo "   ✗ Integration test binary failed to build"
    exit 1
fi

# Test 4: Check Docker Compose configuration
echo "✅ Test 4: Docker Compose configuration"
if [ -f "docker-compose.test.yml" ]; then
    echo "   ✓ Docker Compose file exists"
    # Validate docker-compose file
    if docker-compose -f docker-compose.test.yml config > /dev/null 2>&1; then
        echo "   ✓ Docker Compose configuration is valid"
    else
        echo "   ✗ Docker Compose configuration is invalid"
        exit 1
    fi
else
    echo "   ✗ Docker Compose file missing"
    exit 1
fi

# Test 5: Check if scripts are executable
echo "✅ Test 5: Scripts"
if [ -x "scripts/run-integration-tests.sh" ]; then
    echo "   ✓ run-integration-tests.sh is executable"
else
    echo "   ✗ run-integration-tests.sh is not executable"
    exit 1
fi

if [ -x "scripts/start-integration-tests.sh" ]; then
    echo "   ✓ start-integration-tests.sh is executable"
else
    echo "   ✗ start-integration-tests.sh is not executable"
    exit 1
fi

echo "🎉 All integration setup tests passed!"
echo ""
echo "📋 Next steps:"
echo "   1. Run: ./scripts/start-integration-tests.sh"
echo "   2. This will start Keycloak and run the full integration test suite"
echo "   3. Make sure Docker is running before executing"
echo ""
echo "🔍 What the integration tests will validate:"
echo "   - Keycloak connection and OIDC discovery"
echo "   - Real broker creation with OIDC provider"
echo "   - IPC server setup and communication"
echo "   - Device flow authentication with real Keycloak"
echo "   - Session management with real tokens"
echo "   - SSH key generation and management"
echo "   - Policy evaluation with real user data"
echo "   - Audit logging functionality"
echo "   - Proper cleanup and resource management"