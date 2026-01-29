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

## Example Report
```
Select interface:
  1) Embedded LOM 1 Port 1
  2) Local Area Connection* 10
  3) Ethernet 3
  4) vEthernet (HPE Virtual Switch Adapter #1 - Virtual Switch)
Enter number (1..4): 4
Interface:  vEthernet (HPE Virtual Switch Adapter #1 - Virtual Switch)
MAC:        94:40:C9:12:2F:49
IP:         192.168.30.100/24
Link:       up [ethernet 1.00 Gbps]

Switch / VLAN Info (LLDP)
  System: USW-24-PoETechBenchCenter
  Port:   Port 23
  VLAN:   30
  Chassis:E4:38:83:87:AF:6C

Connectivity Tests
  Ping 8.8.8.8:   8.0 ms
  Ping 1.1.1.1:   8.0 ms
  DNS Lookup:     google.com 142.250.76.110
  HTTPS Test:     200

DHCP Lease / Server Detection
DHCP: sending DISCOVER and listening for OFFER...
  Sent DISCOVER (xid=0x30a5e0eb)
  Listening for 30s...

  DHCP OFFER:
    Your IP:   192.168.30.100
    Server ID: 192.168.30.1
    Router:    192.168.30.1
    DNS:       172.64.36.1 172.64.36.2
    Lease:     24h 0m
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
