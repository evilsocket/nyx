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

# Start the container
echo ""
echo "[*] Starting test container..."
docker-compose up -d

# Wait for container to be ready
echo "[*] Waiting for container to be ready..."
sleep 2

# Run the test sequence
echo ""
echo "[*] Running test sequence..."
docker exec nyx-test bash -c '
    set -e
    
    echo "================================"
    echo "Phase 1: Creating Artifacts"
    echo "================================"
    echo ""
    
    # Switch to testuser for artifact creation
    su - testuser -c "create-artifacts.sh"
    
    echo ""
    echo "================================"
    echo "Phase 2: Running Cleaner"
    echo "================================"
    echo ""
    
    # Run cleaner as root with force flag
    /usr/local/bin/nyx.sh --force
    
    echo ""
    echo "================================"
    echo "Phase 3: Verifying Cleanup"
    echo "================================"
    echo ""
    
    # Verify cleanup as testuser
    su - testuser -c "verify-cleanup.sh"
    
    echo ""
    echo "================================"
    echo "Test Complete!"
    echo "================================"
'

# Capture exit code
EXIT_CODE=$?

# Clean up
echo ""
echo "[*] Cleaning up..."
docker-compose down

echo ""
if [ $EXIT_CODE -eq 0 ]; then
    echo "✅ Test completed successfully!"
    exit 0
else
    echo "❌ Test failed with exit code: $EXIT_CODE"
    exit $EXIT_CODE
fi
