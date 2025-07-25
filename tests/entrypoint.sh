#!/bin/bash
# Entrypoint script for nyx Docker tests

set -e

# Function to run with timeout
run_with_timeout() {
    local timeout=$1
    shift
    local cmd="$@"
    
    echo "[*] Running: $cmd (timeout: ${timeout}s)"
    
    # Run command with timeout
    timeout --preserve-status --signal=TERM --kill-after=10 $timeout bash -c "$cmd"
    local exit_code=$?
    
    if [ $exit_code -eq 124 ]; then
        echo "[ERROR] Command timed out after ${timeout}s"
        return 1
    elif [ $exit_code -eq 137 ]; then
        echo "[ERROR] Command was killed"
        return 1
    fi
    
    return $exit_code
}

# Main test sequence
main() {
    echo "================================"
    echo "Nyx Docker Test - Starting"
    echo "================================"
    echo ""
    
    # Phase 1: Create artifacts
    echo "================================"
    echo "Phase 1: Creating Artifacts"
    echo "================================"
    echo ""
    
    if ! run_with_timeout 180 "su - testuser -c 'create-artifacts.sh'"; then
        echo "[ERROR] Failed to create artifacts"
        exit 1
    fi
    
    echo ""
    echo "================================"
    echo "Phase 2: Running Cleaner"
    echo "================================"
    echo ""
    
    # Run cleaner as root with force flag
    if ! run_with_timeout 600 "/usr/local/bin/nyx.sh --force"; then
        echo "[ERROR] Nyx cleaner failed"
        exit 1
    fi
    
    echo ""
    echo "================================"
    echo "Phase 3: Verifying Cleanup"
    echo "================================"
    echo ""
    
    # Verify cleanup as testuser
    if ! run_with_timeout 180 "su - testuser -c 'verify-cleanup.sh'"; then
        echo "[ERROR] Verification failed"
        exit 1
    fi
    
    echo ""
    echo "================================"
    echo "Test Complete - All Passed!"
    echo "================================"
    
    exit 0
}

# Trap to ensure we don't hang
trap 'echo "[TRAP] Caught signal, exiting..."; exit 1' SIGTERM SIGINT

# Run main with overall timeout
exec timeout --preserve-status --signal=TERM --kill-after=10 300 bash -c "$(declare -f run_with_timeout); $(declare -f main); main"
