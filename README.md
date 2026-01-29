# Network Diagnostic Tool

A CLI tool that replicates some Netool PRO 2 functionality for network diagnostics.

## Features

- Network interface discovery with speed/duplex status
<!--- MAC/IP address scanning and device discovery ARP-->
- LLDP/CDP neighbor discovery
- DHCP information gathering
<!--- Port scanning and service detection nmap-->
<!--- Packet capture capability pcap-->
<!--- Parallel execution for optimal performance-->
- Plain text report generation

## Usage

```bash
# network report go build
sudo ./netool -i eth0
# network report zig build
sudo ./netool
```

## Zig build

https://ziglang.org/documentation/0.14.1/#Build-Mode

```bash
zig build -Doptimize=ReleaseFast
```

## Go Build

```bash
make build
```

## Requirements

- Root privileges for full functionality
- Go 1.19+
- Zig 0.15.2
