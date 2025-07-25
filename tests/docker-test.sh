#!/bin/bash
# Automated test script for nyx in Docker

set -e

echo "========================================="
echo "Nyx Docker Test"
echo "========================================="
echo ""

# Check if Docker is running
if ! docker info >/dev/null 2>&1; then
    echo "Error: Docker is not running"
    exit 1
fi

# Detect docker compose command (v1 vs v2)
if command -v docker-compose >/dev/null 2>&1; then
    DOCKER_COMPOSE="docker-compose"
elif docker compose version >/dev/null 2>&1; then
    DOCKER_COMPOSE="docker compose"
else
    echo "Error: docker-compose not found. Please install Docker Compose."
    exit 1
fi

# Clean up any existing container
echo "[*] Cleaning up existing containers..."
$DOCKER_COMPOSE down 2>/dev/null || true

# Build the Docker image
echo "[*] Building Docker image..."
$DOCKER_COMPOSE build

# Start the container and run tests
echo ""
echo "[*] Starting test container and running tests..."

# Run the container with the entrypoint script
# The container will execute the test sequence and exit with appropriate code
EXIT_CODE=0
$DOCKER_COMPOSE run --rm nyx-test || EXIT_CODE=$?

# No need for manual cleanup as --rm removes the container

echo ""
if [ $EXIT_CODE -eq 0 ]; then
    echo "✅ Test completed successfully!"
    exit 0
else
    echo "❌ Test failed with exit code: $EXIT_CODE"
    exit $EXIT_CODE
fi
