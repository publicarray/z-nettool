//go:build linux

package main

import (
	"crypto/tls"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const (
	dhcpClientPort = 68
	dhcpServerPort = 67
	DHCPDiscover   = 1
	DHCPOffer      = 2
	DHCPTimeout    = 10
)

func main() {
	ifaceName := flag.String("i", "", "Network interface to test")
	flag.Parse()
	if *ifaceName == "" {
		log.Fatal("Please specify an interface with -i")
	}

	fmt.Println(color.New(color.FgCyan, color.Bold).Sprint("=== Network Report ==="))

	printInterfaceInfo(*ifaceName)
	printLLDP(*ifaceName)
	printConnectivity(*ifaceName)
	printDHCP(*ifaceName)
}

// ---------------- Interface Info ----------------
func printInterfaceInfo(ifaceName string) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatal(err)
	}

	addrs, _ := iface.Addrs()
	ip := "[not assigned]"
	if len(addrs) > 0 {
		ip = addrs[0].String()
	}

	linkInfo := getLinkInfo(ifaceName)

	fmt.Println("\n  Interface: ", ifaceName)
	fmt.Println("  MAC:       ", iface.HardwareAddr)
	fmt.Println("  IP:        ", ip)
	fmt.Println("  Link:      ", linkInfo)
}

// Get link speed/duplex from ethtool
func getLinkInfo(iface string) string {
	out, err := exec.Command("ethtool", iface).Output()
	if err != nil {
		return "[unknown]"
	}
	lines := strings.Split(string(out), "\n")
	speed, duplex := "", ""
	for _, l := range lines {
		if strings.Contains(l, "Speed:") {
			speed = strings.TrimSpace(strings.SplitN(l, ":", 2)[1])
		}
		if strings.Contains(l, "Duplex:") {
			duplex = strings.TrimSpace(strings.SplitN(l, ":", 2)[1])
		}
	}
	if speed != "" && duplex != "" {
		num, _ := strconv.ParseInt(speed, 10, 64)
		if num > 1000 {
			return fmt.Sprintf(color.New(color.FgBlue).Sprint(speed), duplex)
		} else if strings.Contains(speed, "1000") {
			return fmt.Sprintf(color.New(color.FgGreen).Sprint(speed), duplex)
		} else {
			return fmt.Sprintf(color.New(color.FgYellow).Sprint(speed+" (Slow Link)"), duplex)
		}
	}

	return "[unknown]"
}

// ---------------- LLDP/CDP ----------------
func printLLDP(iface string) {
	fmt.Println("\nSwitch / VLAN Info")
	out, err := exec.Command("lldpctl", iface).Output()
	if err != nil {
		fmt.Println("  [!] lldpctl not found or failed")
		return
	}
	lines := strings.Split(string(out), "\n")
	for _, l := range lines {
		if strings.HasPrefix(l, "SysName:") ||
			strings.HasPrefix(l, "PortID:") ||
			strings.HasPrefix(l, "PortDescr:") ||
			strings.HasPrefix(l, "VLAN:") {
			fmt.Println(" ", l)
		}
	}
}

// ---------------- Connectivity ----------------
func printConnectivity(iface string) {
	fmt.Println("\nConnectivity Tests")

	pingHost := func(host string) string {
		out, err := exec.Command("ping", "-c", "1", "-I", iface, host).Output()
		if err != nil {
			return color.New(color.FgRed).Sprint("[fail]")
		}
		lines := strings.Split(string(out), "\n")
		for _, l := range lines {
			if strings.Contains(l, "time=") {
				return color.New(color.FgGreen).Sprint(strings.Split(strings.Split(l, "time=")[1], " ")[0] + " ms")
			}
		}
		return color.New(color.FgRed).Sprint("[fail]")
	}

	fmt.Println("  Ping 8.8.8.8:  ", pingHost("8.8.8.8"))
	fmt.Println("  Ping 1.1.1.1:  ", pingHost("1.1.1.1"))

	// DNS
	addrs, err := net.LookupHost("google.com")
	if err != nil {
		fmt.Println("  DNS Lookup:     google.com", color.New(color.FgRed).Sprint("[fail]"))
	} else {
		fmt.Println("  DNS Lookup:     google.com", color.New(color.FgGreen).Sprint(addrs[0]))
	}

	// HTTPS test
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	resp, err := client.Get("https://google.com")
	if err != nil {
		fmt.Println("  HTTPS Test:    ", color.New(color.FgRed).Sprint("[fail]"))
	} else {
		fmt.Println("  HTTPS Test:    ", color.New(color.FgGreen).Sprint(resp.Status))
		resp.Body.Close()
	}
}

// ---------------- DHCP (broadcast like Nmap) ----------------
func printDHCP(iface string) {
	fmt.Println("\nDHCP Lease / Server Detection")
	DHCPBroadcastDiscover(iface, DHCPTimeout)
}

// send a raw DHCP DISCOVER via pcap and capture offers
func DHCPBroadcastDiscover(ifaceName string, timeoutSec int) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatal("Interface error:", err)
	}

	handle, err := pcap.OpenLive(ifaceName, 1600, true, 1*time.Second)
	// handle, err := pcap.OpenLive(ifaceName, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal("pcap open error:", err)
	}
	defer handle.Close()

	// BPF filter: only DHCP server/client UDP ports
	if err := handle.SetBPFFilter("udp and (port 67 or 68)"); err != nil {
		log.Fatal("BPF filter error:", err)
	}

	// Build DHCP DISCOVER
	dhcp := layers.DHCPv4{
		Operation:    layers.DHCPOpRequest,
		HardwareType: 1, // Ethernet
		HardwareLen:  6, // MAC length
		Xid:          0x12345678,
		Flags:        0x8000, // broadcast
		ClientHWAddr: iface.HardwareAddr,
		Options: layers.DHCPOptions{
			{Type: layers.DHCPOptMessageType, Length: 1, Data: []byte{DHCPDiscover}},
			{Type: layers.DHCPOptEnd},
		},
	}

	udp := layers.UDP{SrcPort: 68, DstPort: 67}
	udp.SetNetworkLayerForChecksum(&layers.IPv4{SrcIP: net.IPv4zero, DstIP: net.IPv4bcast})

	ip := layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    net.IPv4zero,
		DstIP:    net.IPv4bcast,
	}

	eth := layers.Ethernet{
		SrcMAC:       iface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeIPv4,
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, &eth, &ip, &udp, &dhcp); err != nil {
		log.Fatal("Failed to serialize DHCP DISCOVER:", err)
	}

	// Send raw packet via pcap
	if err := handle.WritePacketData(buf.Bytes()); err != nil {
		log.Fatal("Failed to send DHCP DISCOVER:", err)
	}
	fmt.Println("  Sent DHCP DISCOVER broadcast")

	// Listen for offers
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	timeout := time.After(time.Duration(timeoutSec) * time.Second)

	fmt.Printf("  Listening for DHCP offers (%ds)...\n", timeoutSec)
	offersFound := 0

	for {
		select {
		case packet := <-packetSource.Packets():
			dhcpLayer := packet.Layer(layers.LayerTypeDHCPv4)
			if dhcpLayer == nil {
				continue
			}
			dhcpResp, _ := dhcpLayer.(*layers.DHCPv4)

			// Find message type
			var msgType byte
			var leaseTime uint32
			var router, server, dns string
			for _, opt := range dhcpResp.Options {
				switch opt.Type {
				case layers.DHCPOptMessageType:
					msgType = opt.Data[0]
				case layers.DHCPOptLeaseTime:
					leaseTime = binary.BigEndian.Uint32(opt.Data)
				case layers.DHCPOptRouter:
					router = net.IP(opt.Data).String()
				case layers.DHCPOptServerID:
					server = net.IP(opt.Data).String()
				case layers.DHCPOptDNS:
					for i := 0; i < len(opt.Data); i += 4 {
						dns += net.IP(opt.Data[i:i+4]).String() + " "
					}
				}
			}

			if msgType == DHCPOffer {
				fmt.Println("\n  DHCP OFFER:")
				fmt.Println("    IP Offered: ", dhcpResp.YourClientIP)
				fmt.Println("    Server:     ", server)
				fmt.Printf("    Lease Time: %dh %dm\n", leaseTime/3600, (leaseTime%3600)/60)
				if router != "" {
					fmt.Println("    Router:     ", router)
				}
				if dns != "" {
					fmt.Println("    DNS:        ", dns)
				}
				offersFound++
			}

		case <-timeout:
			if offersFound == 0 {
				fmt.Println("  [!] No DHCP offers received")
			}
			return
		}
	}
}
