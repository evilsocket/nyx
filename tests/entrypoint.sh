#!/bin/bash
# Entrypoint script for Docker test container

set -e

echo "================================"
echo "Nyx Docker Test - Starting"
echo "================================"
echo ""

# Function to run a command with timeout and capture output
run_with_timeout() {
    local cmd="$1"
    local timeout="$2"
    local desc="$3"
    
    echo "[*] Running: $cmd (timeout: ${timeout}s)"
    
    # Run command with timeout
    if timeout "$timeout" bash -c "$cmd" 2>&1; then
        return 0
    else
        local exit_code=$?
        if [ $exit_code -eq 124 ]; then
            echo "[ERROR] Command timed out after ${timeout}s"
        else
            echo "[ERROR] Command failed with exit code: $exit_code"
        fi
        return $exit_code
    fi
}

# Phase 1: Create artifacts
echo "================================"
echo "Phase 1: Creating Artifacts"
echo "================================"
echo ""

if ! run_with_timeout "su - testuser -c 'create-artifacts.sh'" 180 "Create artifacts"; then
    echo "[ERROR] Failed to create artifacts"
    exit 1
fi

echo ""
echo "================================"
echo "Phase 2: Running Cleaner"
echo "================================"
echo ""

# Run nyx.sh as root with force flag
if ! run_with_timeout "/usr/local/bin/nyx.sh --force" 600 "Run nyx cleaner"; then
    echo "[ERROR] Failed to run nyx cleaner"
    exit 2
fi

echo ""
echo "================================"
echo "Phase 3: Verifying Cleanup"
echo "================================"
echo ""

# Verify cleanup
if ! run_with_timeout "/usr/local/bin/verify-cleanup.sh" 300 "Verify cleanup"; then
    echo "[ERROR] Verification failed"
    exit 3
fi

echo ""
echo "================================"
echo "Test Complete - All Passed!"
echo "================================"
echo ""

exit 0
