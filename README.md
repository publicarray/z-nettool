# Network Diagnostic Tool

A Go-based CLI tool that replicates Netool PRO 2 functionality for network diagnostics.

## Features

- Network interface discovery with speed/duplex status
- MAC/IP address scanning and device discovery
- LLDP/CDP neighbor discovery
- DHCP information gathering
<!--- Port scanning and service detection-->
<!--- Packet capture capability-->
<!--- Parallel execution for optimal performance-->
- Plain text report generation

## Usage

```bash
# network report
sudo ./netool -i eth0

```

## Build

```bash
make build
```

## Requirements

- Root privileges for full functionality
- Linux system
- Go 1.19+

## License

MIT
