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

# Clean up any existing container
echo "[*] Cleaning up existing containers..."
docker-compose down 2>/dev/null || true

# Build the Docker image
echo "[*] Building Docker image..."
docker-compose build

# Start the container and run tests
echo ""
echo "[*] Starting test container and running tests..."

# Run the container with the entrypoint script
# The container will execute the test sequence and exit with appropriate code
EXIT_CODE=0
docker-compose run --rm nyx-test || EXIT_CODE=$?

# No need for manual cleanup as --rm removes the container

echo ""
if [ $EXIT_CODE -eq 0 ]; then
    echo "✅ Test completed successfully!"
    exit 0
else
    echo "❌ Test failed with exit code: $EXIT_CODE"
    exit $EXIT_CODE
fi
