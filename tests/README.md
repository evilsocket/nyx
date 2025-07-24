# Nyx Test Suite

This directory contains a comprehensive test suite for Nyx, the anti-forensics trace cleaner. The tests use Docker with systemd support to provide a realistic Linux environment for testing all cleaning modules.

## Test Files

### Core Test Scripts

- **create-artifacts.sh** - Creates comprehensive forensic artifacts for testing
  - Shell histories (14 types including R, GDB, MongoDB, Docker)
  - System logs with suspicious entries and NYX-TEST markers
  - Audit logs with NYXTEST events
  - Package manager logs with evilpkg entries
  - Temporary files, scripts, and core dumps
  - Thumbnail caches (both .cache/thumbnails and .thumbnails)
  - GNOME Tracker databases and indexes
  - Zeitgeist activity logs
  - NetworkManager connection profiles
  - Trash directories with metadata
  - Journald entries with markers

- **verify-cleanup.sh** - Comprehensive verification of artifact cleanup
  - Strict size-zero checks for history files
  - Marker-based verification for logs (NYX-TEST, NYXTEST, evilpkg)
  - Fail-fast approach with clear error messages
  - Tracker database search verification
  - NetworkManager profile checks
  - Journald and audit log marker verification
  - Complete thumbnail cache validation

### Docker Test Environment

- **docker-test.sh** - Automated test runner
  - Builds Docker image with systemd support
  - Creates artifacts as testuser
  - Runs Nyx cleaner as root
  - Verifies cleanup with strict checks
  - Automatic cleanup on completion

- **Dockerfile** - Ubuntu 22.04 with systemd
  - Full systemd support for realistic testing
  - Includes: auditd, NetworkManager, tracker, zeitgeist
  - ImageMagick for thumbnail generation
  - All shell types and database clients
  - Configured for privileged operations

- **docker-compose.yml** - Container orchestration
  - Systemd-enabled container configuration
  - Proper cgroup mounting for systemd
  - Volume mounts for test scripts
  - Security options for full system access

## Running Tests

### Quick Test (Recommended)
```bash
cd tests
./docker-test.sh
```

This will:
1. Build the test container
2. Start systemd services
3. Create comprehensive artifacts
4. Run Nyx with --force flag
5. Verify all traces are cleaned
6. Clean up the container

### Manual Testing
```bash
# Start container with systemd
docker-compose up -d

# Wait for initialization
sleep 5

# Enter container
docker exec -it nyx-test bash

# Create artifacts as testuser
su - testuser -c "create-artifacts.sh"

# Run cleaner as root
sudo nyx.sh --force

# Verify cleanup as testuser
su - testuser -c "verify-cleanup.sh"

# Exit and cleanup
exit
docker-compose down
```

## Test Coverage

### Linux Artifacts Tested
- **Shell Histories**: 14 types with injected commands
- **System Logs**: 25+ log types with suspicious entries
- **Package Manager**: dpkg, apt with evilpkg markers
- **Audit Logs**: auditd with NYXTEST events
- **Network Traces**: ARP cache, NetworkManager profiles
- **User Traces**: 
  - Thumbnails (new and old locations)
  - GNOME Tracker databases
  - Zeitgeist activity logs
  - Trash directories with metadata
- **Temporary Files**: Scripts, hidden files, core dumps
- **Journald**: Entries with NYX-TEST markers

### Test Philosophy
- **Deterministic**: Uses specific markers (NYX-TEST, NYXTEST, evilpkg) for reliable verification
- **Strict Validation**: Uses `-s` flag to ensure files are truly empty
- **Fail-Fast**: First unmet expectation exits with clear reason
- **Comprehensive**: Tests all new features added to Nyx
- **Realistic**: Uses systemd for proper service behavior

## Requirements

- Docker and Docker Compose
- Linux host (for privileged container operations)
- ~2GB disk space for Docker image
- Systemd-compatible Docker setup

## Troubleshooting

### Container Won't Start
- Ensure Docker daemon supports systemd containers
- Check cgroup v2 compatibility
- Verify privileged mode is allowed

### Tests Fail
- Check if services are running: `docker exec nyx-test systemctl status`
- Verify artifact creation: `docker exec nyx-test ls -la /home/testuser/`
- Check logs: `docker logs nyx-test`

### Manual Debugging
```bash
# Keep container running after test
docker-compose up -d
docker exec -it nyx-test bash

# Check specific services
systemctl status auditd
systemctl status NetworkManager
tracker3 status

# Run individual test steps
su - testuser
create-artifacts.sh
exit
nyx.sh --dry-run --debug
```

## Adding New Tests

To add tests for new artifacts:

1. **In create-artifacts.sh**:
   - Add artifact creation with deterministic markers
   - Use specific strings that can be grepped reliably

2. **In verify-cleanup.sh**:
   - Add strict verification (prefer `-s` checks)
   - Use `fail()` for immediate failure feedback
   - Check for your specific markers

3. **Update Documentation**:
   - Add to this README's coverage section
   - Update main README.md if needed

## CI Integration

The test suite is designed for CI/CD pipelines:

```yaml
# Example GitHub Actions
- name: Run Nyx Tests
  run: |
    cd tests
    ./docker-test.sh
```

Exit codes:
- 0: All tests passed
- 1: One or more artifacts not cleaned
- Other: Docker or script errors
