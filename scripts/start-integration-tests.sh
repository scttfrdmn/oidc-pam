#!/bin/bash

set -e

echo "🚀 Starting OIDC PAM Integration Test Environment"

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "❌ Docker is not running. Please start Docker first."
    exit 1
fi

# Check if Docker Compose is available
if ! command -v docker-compose > /dev/null 2>&1; then
    echo "❌ docker-compose is not installed. Please install Docker Compose."
    exit 1
fi

# Clean up any existing containers
echo "🧹 Cleaning up existing containers..."
docker-compose -f docker-compose.test.yml down --volumes --remove-orphans || true

# Build and start services
echo "🏗️  Building and starting services..."
docker-compose -f docker-compose.test.yml up --build --abort-on-container-exit

# Capture exit code
EXIT_CODE=$?

# Clean up
echo "🧹 Cleaning up..."
docker-compose -f docker-compose.test.yml down --volumes --remove-orphans

if [ $EXIT_CODE -eq 0 ]; then
    echo "✅ Integration tests completed successfully!"
else
    echo "❌ Integration tests failed with exit code $EXIT_CODE"
    exit $EXIT_CODE
fi