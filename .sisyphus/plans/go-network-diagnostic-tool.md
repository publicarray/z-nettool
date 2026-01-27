# Go Network Diagnostic Tool (Netool PRO 2 Clone)

## Context

### Original Request
Create a small Go app that provides the same functionality as Netool PRO 2 - a portable network diagnostic tool that can show network link status, display device MAC addresses and IPs on switch ports, run cable testing, do LLDP/CDP switch neighbor discovery, capture packets, scan networks, provide port scanning/service detection, and gather DHCP info to create reports.

### Interview Summary
**Key Discussions**:
- **Cable testing**: User decided to SKIP (acknowledged hardware limitations for true TDR)
- **Report format**: Plain text - human-readable terminal output
- **Privileges**: Root access acceptable for full functionality
- **Deployment**: Single binary executable
- **CLI style**: Flags with comprehensive default scan
- **Execution**: Parallel scanning where possible for performance
- **Testing**: Use Go's built-in testing framework

**Research Findings**:
- **gopacket/gopacket**: Industry standard for packet capture and analysis with extensive protocol support
- **insomniacslk/dhcp**: Complete DHCPv4/v6 implementation for gathering DHCP information
- **robgonnella/go-lanscan**: Network scanning and discovery functionality
- **irai/packet**: ARP/ICMP processing with device online/offline notifications
- **Cable testing**: True TDR requires specialized hardware, software-only solutions limited to basic continuity

### Self-Review Gap Analysis
**Identified and Addressed Gaps**:
- **Root privilege handling**: Added explicit permission checks and graceful fallbacks
- **Parallel execution coordination**: Implemented goroutine-safe result collection
- **Error handling for missing network interfaces**: Added robust interface detection
- **Report format structure**: Defined clear plain text layout with sections
- **Build process**: Included static compilation for single binary deployment

---

## Work Objectives

### Core Objective
Build a Go CLI tool that replicates Netool PRO 2 functionality by performing comprehensive network diagnostics and generating plain text reports, with parallel execution and single binary deployment.

### Concrete Deliverables
- Single executable binary: `netool` 
- Comprehensive network diagnostic functionality
- Plain text report generation
- Go test suite with unit tests

### Definition of Done
- [ ] `go build` produces single binary executable
- [ ] `sudo ./netool` runs comprehensive scan and produces text report
- [ ] Individual scan modules work with respective flags
- [ ] `go test ./...` passes all tests
- [ ] Binary works on target Linux system without dependencies

### Must Have
- Network interface discovery with speed/duplex status
- MAC/IP address scanning and device discovery
- LLDP/CDP neighbor discovery
- DHCP information gathering
- Port scanning and service detection
- Packet capture capability
- Parallel execution of scans
- Plain text report output
- Single binary compilation

### Must NOT Have (Guardrails)
- Cable testing functionality (hardware limitation)
- Web interface or GUI components
- Multiple output formats (text only)
- External dependencies beyond Go modules
- Database storage or persistent data

---

## Verification Strategy

### Test Decision
- **Infrastructure exists**: NO (new project)
- **User wants tests**: YES (Go testing framework)
- **Framework**: Go built-in testing with `go test`

### TDD Workflow Applied

Each TODO follows RED-GREEN-REFACTOR:

**Task Structure:**
1. **RED**: Write failing test first
   - Test file: `[module]_test.go`
   - Test command: `go test ./...`
   - Expected: FAIL (test exists, implementation doesn't)
2. **GREEN**: Implement minimum code to pass
   - Command: `go test ./...`
   - Expected: PASS
3. **REFACTOR**: Clean up while keeping green
   - Command: `go test ./...`
   - Expected: PASS (still)

**Test Setup Tasks:**
- [ ] 0.1 Initialize Go module
  - Command: `go mod init github.com/user/network-diag`
  - Verify: `go.mod` file created
- [ ] 0.2 Setup test structure
  - Create `pkg/` directory structure
  - Create `*_test.go` files
  - Verify: `go test ./...` → discovers tests

### Manual Execution Verification (ALWAYS include, even with tests)

**By Deliverable Type:**

| Type | Verification Tool | Procedure |
|------|------------------|-----------|
| **CLI Application** | interactive_bash (tmux) | Run command, verify output |
| **Network Scans** | System network tools | Compare with standard tools |
| **Binary Build** | Go compiler | Verify single binary creation |

**Evidence Required:**
- Commands run with actual output
- Binary size and functionality verification
- Network scan results compared to standard tools

---

## Task Flow

```
Project Setup → Core Modules → CLI Interface → Integration → Testing
                    ↘ Parallel execution coordination throughout
```

## Parallelization

| Group | Tasks | Reason |
|-------|-------|--------|
| A | 1, 2 | Independent module setup |

| Task | Depends On | Reason |
|------|------------|--------|
| 3+ | 1, 2 | Requires project structure |
| 7 | 3-6 | Requires module implementations |
| 8 | 7 | Integration after modules complete |

---

## TODOs

- [ ] 0.1 Initialize Go project structure
  - Create `go.mod` with module name
  - Create directory structure: `cmd/`, `pkg/`, `internal/`
  - Add basic `README.md` and `LICENSE`
  - Verify: `go mod tidy` succeeds

  **Must NOT do**:
  - Add external build tools or complex dependencies

  **Parallelizable**: NO (foundation task)

  **References**:
  **Pattern References**:
  - Standard Go project layout from golang-standards/project-layout
  - `gopacket/gopacket` repository structure for reference

  **Acceptance Criteria**:
  - [ ] `go.mod` exists with correct module name
  - [ ] Directory structure created
  - [ ] `go mod tidy` runs without errors
  - [ ] `go build ./cmd/netool` creates executable

- [ ] 0.2 Setup Go testing infrastructure
  - Create `_test.go` files for each package
  - Setup test utilities and mocks
  - Add basic example tests
  - Verify: `go test ./...` → 0 failures

  **Must NOT do**:
  - Add external testing frameworks

  **Parallelizable**: NO (foundation task)

  **References**:
  **Pattern References**:
  - Go testing best practices from Go documentation
  - Test examples from gopacket library

  **Acceptance Criteria**:
  - [ ] Test files exist for each package
  - [ ] `go test ./...` discovers all tests
  - [ ] Example test passes

- [ ] 1.1 Network interface discovery module
  - Implement interface enumeration using `net` package
  - Get speed/duplex information via syscalls
  - Handle interface status (up/down, connected)
  - Add error handling for permission issues

  **Must NOT do**:
  - Rely on external tools like `ifconfig` or `ip`

  **Parallelizable**: YES (with 2.1, 3.1)

  **References**:
  **Pattern References**:
  - Go `net` package documentation
  - Linux syscalls for network interface info
  - Error handling patterns in Go standard library

  **Acceptance Criteria**:
  - [ ] Test file: `pkg/interfaces/interfaces_test.go`
  - [ ] `go test ./pkg/interfaces` → PASS
  - [ ] Returns list of network interfaces with status
  - [ ] Handles missing permissions gracefully

  **Manual Verification**:
  - [ ] `go run ./cmd/netool --interfaces` → lists interfaces
  - [ ] Compare output with `ip link show`

- [ ] 1.2 MAC/IP address scanning module
  - Implement ARP scanning for network discovery
  - Active IP range scanning with configurable timeouts
  - MAC address vendor lookup integration
  - Thread-safe result collection

  **Must NOT do**:
  - Flood network with excessive traffic

  **Parallelizable**: YES (with 2.2, 3.2)

  **References**:
  **Pattern References**:
  - `irai/packet` library for ARP handling
  - `golang.org/x/net/icmp` for ping functionality
  - goroutine patterns for concurrent scanning

  **Acceptance Criteria**:
  - [ ] Test file: `pkg/discovery/discovery_test.go`
  - [ ] `go test ./pkg/discovery` → PASS
  - [ ] Scans local network segment
  - [ ] Returns MAC/IP pairs with vendor info

  **Manual Verification**:
  - [ ] `sudo ./netool --scan 192.168.1.0/24` → discovers devices
  - [ ] Compare with `nmap -sn` results

- [ ] 2.1 LLDP/CDP neighbor discovery module
  - Implement LLDP packet parsing and sending
  - Add CDP support (Cisco Discovery Protocol)
  - Parse neighbor information and capabilities
  - Handle passive vs active discovery modes

  **Must NOT do**:
  - Implement proprietary protocols beyond LLDP/CDP

  **Parallelizable**: YES (with 1.1, 3.1)

  **References**:
  **Pattern References**:
  - `gopacket/layers` for LLDP/CDP packet structures
  - IEEE 802.1AB LLDP specification
  - CDP protocol documentation

  **Acceptance Criteria**:
  - [ ] Test file: `pkg/lldp/lldp_test.go`
  - [ ] `go test ./pkg/lldp` → PASS
  - [ ] Discovers LLDP neighbors on switch ports
  - [ ] Parses switch chassis ID, port ID, capabilities

  **Manual Verification**:
  - [ ] `sudo ./netool --lldp` → shows switch information
  - [ ] Compare with `lldpctl` output if available

- [ ] 2.2 DHCP information gathering module
  - Implement DHCP client functionality
  - Send DHCP discover and parse responses
  - Extract DHCP server info, options, lease parameters
  - Handle both DHCPv4 and DHCPv6

  **Must NOT do**:
  - Actually modify system network configuration

  **Parallelizable**: YES (with 1.2, 3.2)

  **References**:
  **Pattern References**:
  - `insomniacslk/dhcp` library implementation
  - RFC 2131 DHCP specification
  - DHCP options parsing patterns

  **Acceptance Criteria**:
  - [ ] Test file: `pkg/dhcp/dhcp_test.go`
  - [ ] `go test ./pkg/dhcp` → PASS
  - [ ] Sends DHCP discover packets
  - [ ] Parses DHCP server responses

  **Manual Verification**:
  - [ ] `sudo ./netool --dhcp` → shows DHCP server info
  - [ ] Compare with `dhclient -r` output

- [ ] 3.1 Port scanning and service detection module
  - TCP/UDP port scanning with configurable ranges
  - Service fingerprinting and version detection
  - Concurrent scanning with rate limiting
  - Common service banner extraction

  **Must NOT do**:
  - Perform aggressive or destructive scans

  **Parallelizable**: YES (with 1.1, 2.1)

  **References**:
  **Pattern References**:
  - Port scanning algorithms from nmap source
  - Go `net` package for TCP/UDP connections
  - goroutine pools for concurrent connections

  **Acceptance Criteria**:
  - [ ] Test file: `pkg/portscan/portscan_test.go`
  - [ ] `go test ./pkg/portscan` → PASS
  - [ ] Scans common ports (1-1000) by default
  - [ ] Detects open/closed/filtered states

  **Manual Verification**:
  - [ ] `./netool --portscan 192.168.1.1` → shows open ports
  - [ ] Compare with `nmap` results for same target

- [ ] 3.2 Packet capture module
  - Live packet capture with filtering
  - Protocol decoding and analysis
  - Configurable capture duration and packet limits
  - BPF filter support for efficient capture

  **Must NOT do**:
  - Store packets permanently or write large files

  **Parallelizable**: YES (with 1.2, 2.2)

  **References**:
  **Pattern References**:
  - `gopacket/pcap` for live capture
  - BPF filter syntax and implementation
  - Memory management for packet buffers

  **Acceptance Criteria**:
  - [ ] Test file: `pkg/capture/capture_test.go`
  - [ ] `go test ./pkg/capture` → PASS
  - [ ] Captures packets from specified interface
  - [ ] Applies BPF filters correctly

  **Manual Verification**:
  - [ ] `sudo ./netool --capture -i eth0 -c 10` → captures 10 packets
  - [ ] Compare with `tcpdump` output

- [ ] 4.1 Main CLI application structure
  - Command-line argument parsing with flags
  - Orchestrate parallel execution of modules
  - Coordinate result collection and reporting
  - Handle root privilege checks

  **Must NOT do**:
  - Create complex subcommand structure

  **References**:
  **Pattern References**:
  - Go `flag` package usage
  - Go concurrency patterns with goroutines
  - Error handling and logging patterns

  **Acceptance Criteria**:
  - [ ] Test file: `cmd/netool/main_test.go`
  - [ ] `go test ./cmd/netool` → PASS
  - [ ] Parses all command-line flags correctly
  - [ ] Runs default comprehensive scan

  **Manual Verification**:
  - [ ] `./netool --help` → shows usage and flags
  - [ ] `sudo ./netool` → runs full scan

- [ ] 4.2 Report generation module
  - Format results as plain text sections
  - Include timestamps and execution metadata
  - Handle different verbosity levels
  - Ensure thread-safe output formatting

  **Must NOT do**:
  - Implement multiple output formats

  **Parallelizable**: NO (depends on all modules)

  **References**:
  **Pattern References**:
  - Go `fmt` package for formatted output
  - Text formatting and table structures
  - String builder patterns for performance

  **Acceptance Criteria**:
  - [ ] Test file: `pkg/report/report_test.go`
  - [ ] `go test ./pkg/report` → PASS
  - [ ] Generates readable text report
  - [ ] Includes all scan results

  **Manual Verification**:
  - [ ] `sudo ./netool` → produces complete report
  - [ ] Report format is readable and complete

- [ ] 5.1 Integration and parallel coordination
  - Implement goroutine-safe result collection
  - Coordinate concurrent module execution
  - Handle timeouts and cancellation
  - Aggregate results from all modules

  **Must NOT do**:
  - Create blocking dependencies between modules

  **Parallelizable**: NO (integration task)

  **References**:
  **Pattern References**:
  - Go `sync` package for coordination
  - Context package for cancellation
  - Channel patterns for result collection

  **Acceptance Criteria**:
  - [ ] Test file: `internal/coordinator/coordinator_test.go`
  - [ ] `go test ./internal/coordinator` → PASS
  - [ ] Runs all modules concurrently
  - [ ] Collects results without races

  **Manual Verification**:
  - [ ] `sudo ./netool` completes all scans
  - [ ] Performance measured against sequential execution

- [ ] 6.1 Build system and single binary compilation
  - Setup Makefile or build script
  - Configure static compilation for single binary
  - Add version information and build metadata
  - Test binary on clean system

  **Must NOT do**:
  - Require external build dependencies

  **Parallelizable**: NO (build system)

  **References**:
  **Pattern References**:
  - Go build tags and ldflags
  - Static compilation techniques
  - Cross-compilation best practices

  **Acceptance Criteria**:
  - [ ] Build script exists and works
  - [ ] `make build` → creates single binary
  - [ ] Binary runs on clean system
  - [ ] Binary size is reasonable (<20MB)

  **Manual Verification**:
  - [ ] `make build` → produces netool binary
  - [ ] `ldd netool` → shows "not a dynamic executable"
  - [ ] Copy to clean system → runs without dependencies

- [ ] 7.1 Comprehensive testing and validation
  - End-to-end integration tests
  - Performance benchmarks
  - Error handling validation
  - Compatibility testing across systems

  **Must NOT do**:
  - Skip unit tests in favor of only integration tests

  **Parallelizable**: NO (final validation)

  **References**:
  **Pattern References**:
  - Go testing patterns and benchmarks
  - Table-driven tests in Go
  - Test coverage analysis

  **Acceptance Criteria**:
  - [ ] All tests pass: `go test ./...`
  - [ ] Test coverage >80%
  - [ ] Benchmarks run successfully
  - [ ] Integration tests validate full workflow

  **Manual Verification**:
  - [ ] `go test -cover ./...` → shows coverage report
  - [ ] `go test -bench ./...` → runs benchmarks
  - [ ] Full integration test runs end-to-end

---

## Commit Strategy

| After Task | Message | Files | Verification |
|------------|---------|-------|--------------|
| 0.1 | `feat: initialize Go project structure` | go.mod, directories | go mod tidy |
| 0.2 | `test: setup testing infrastructure` | *_test.go files | go test ./... |
| 1.x | `feat: implement interfaces module` | pkg/interfaces/* | go test ./pkg/interfaces |
| 2.x | `feat: implement discovery module` | pkg/discovery/* | go test ./pkg/discovery |
| 3.x | `feat: implement scanning module` | pkg/portscan/* | go test ./pkg/portscan |
| 4.x | `feat: implement CLI and reporting` | cmd/netool/*, pkg/report/* | go test ./cmd/netool |
| 5.x | `feat: integrate parallel coordination` | internal/coordinator/* | go test ./internal/coordinator |
| 6.x | `build: setup single binary compilation` | Makefile, build scripts | make build |
| 7.x | `test: comprehensive validation` | tests, benchmarks | go test ./... |

---

## Success Criteria

### Verification Commands
```bash
# Build and basic functionality
go mod tidy
go build ./cmd/netool
./netool --help

# Testing
go test ./...  # All tests pass
go test -cover ./...  # Coverage >80%

# Full functionality (requires root)
sudo ./netool  # Comprehensive scan
sudo ./netool --interfaces  # Interface discovery
sudo ./netool --scan 192.168.1.0/24  # Network scan
sudo ./netool --lldp  # LLDP discovery
sudo ./netool --dhcp  # DHCP info
sudo ./netool --portscan 192.168.1.1  # Port scan
sudo ./netool --capture -i eth0 -c 10  # Packet capture

# Build verification
make build
ldd netool  # Should show static binary
```

### Final Checklist
- [ ] All "Must Have" features implemented
- [ ] All "Must NOT Have" exclusions respected
- [ ] Single binary compilation works
- [ ] All tests pass with good coverage
- [ ] Root privilege handling works correctly
- [ ] Parallel execution improves performance
- [ ] Plain text reports are readable and complete
- [ ] Tool works on clean Linux system without dependencies