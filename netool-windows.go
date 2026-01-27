//go:build windows

package main

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"github.com/StackExchange/wmi"
	"github.com/fatih/color"
)

const (
	CaptureTime = 3 // seconds to listen for DHCP offers
)

type DHCPServer struct {
	ServerIP  string
	Offered   []string
	Router    string
	DNS       []string
	LeaseTime string
	Offers    int
}

func main() {
	ifaceName := flag.String("i", "", "Network interface name")
	flag.Parse()

	var err error

	if *ifaceName == "" {
		log.Println("Use -i <interface> with the interface name: e.g 'WiFi' or 'Ethernet'. Use Get-NetAdapter to get the name")
	}
	if *ifaceName == "" {
		var iface *net.Interface
		iface, err = getActiveInterface()
		if err != nil {
			log.Fatal("No active network interface found:", err)
		}
		*ifaceName = iface.Name
	}

	fmt.Println(color.New(color.FgCyan, color.Bold).Sprint("=== Network Report ==="))

	printInterfaceInfo(*ifaceName)
	printConnectivity()
	printDHCP(*ifaceName)

	fmt.Println("\nPress ENTER to exit...")
	fmt.Scanln()
}

func getActiveInterface() (*net.Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue // skip down interfaces
		}
		if iface.Flags&net.FlagLoopback != 0 {
			continue // skip loopback
		}
		addrs, _ := iface.Addrs()
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok && ipnet.IP.To4() != nil {
				return &iface, nil // first active interface with IPv4
			}
		}
	}

	return nil, errors.New("no active interface found")
}

// ---------------- Interface Info ----------------

type Win32_NetworkAdapter struct {
	Name  string
	Speed *uint64
}

func printInterfaceInfo(ifaceName string) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatal(err)
	}

	addrs, _ := iface.Addrs()

	ipv4 := "[not assigned]"
	ipv6 := "[not assigned]"

	for _, a := range addrs {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		default:
			continue
		}

		// Skip link-local v6 (fe80::/10) for display
		if ip.To4() != nil {
			// First IPv4 wins
			if ipv4 == "[not assigned]" {
				ipv4 = ip.String()
			}
		} else if ip.To16() != nil {
			if ip.IsLinkLocalUnicast() {
				continue
			}
			// First non-link-local IPv6 wins
			if ipv6 == "[not assigned]" {
				ipv6 = ip.String()
			}
		}
	}

	link := "[unknown]"
	var adapters []Win32_NetworkAdapter
	q := wmi.CreateQuery(&adapters, "")
	if wmi.Query(q, &adapters) == nil {
		for _, a := range adapters {
			if a.Name == ifaceName && a.Speed != nil {
				link = fmt.Sprintf("%d Mbps", *a.Speed/1e6)
			}
		}
	}

	fmt.Println("\nInterface:")
	fmt.Println("  Name:", ifaceName)
	fmt.Println("  MAC: ", iface.HardwareAddr)
	fmt.Println("  IPv4:", ipv4)
	fmt.Println("  IPv6:", ipv6)
	fmt.Println("  Link:", link)
}

// ---------------- Connectivity ----------------

func printConnectivity() {
	fmt.Println("\nConnectivity:")

	ping := func(host string) string {
		out, err := exec.Command("ping", "-n", "1", host).Output()
		if err != nil {
			return "[fail]"
		}
		for _, l := range strings.Split(string(out), "\n") {
			if strings.Contains(l, "time=") {
				return strings.Split(strings.Split(l, "time=")[1], "ms")[0] + " ms"
			}
		}
		return "[fail]"
	}

	fmt.Println("  Ping 8.8.8.8:", ping("8.8.8.8"))
	fmt.Println("  Ping 1.1.1.1:", ping("1.1.1.1"))

	addrs, err := net.LookupHost("google.com")
	if err != nil {
		fmt.Println("  DNS Lookup:     google.com", color.New(color.FgRed).Sprint("[fail]"))
	} else {
		fmt.Println("  DNS Lookup:     google.com", color.New(color.FgGreen).Sprint(addrs[0]))
	}

	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	client := &http.Client{Timeout: 5 * time.Second, Transport: tr}
	resp, err := client.Get("https://google.com")
	if err != nil {
		fmt.Println("  HTTPS: [fail]")
	} else {
		fmt.Println("  HTTPS:", resp.Status)
		resp.Body.Close()
	}
}

// ---------------- DHCP (direct DHCPDISCOVER / listen for DHCPOFFER) ----------------

func printDHCP(ifaceName string) {
	fmt.Println("\nDHCP Analysis (direct DHCPDISCOVER)")

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		fmt.Println("  [!] Interface lookup failed:", err)
		return
	}
	if len(iface.HardwareAddr) != 6 {
		fmt.Println("  [!] Unexpected MAC length:", len(iface.HardwareAddr))
		return
	}

	servers, err := probeDHCP(iface, time.Duration(CaptureTime)*time.Second)
	if err != nil {
		fmt.Println("  [!] DHCP probe failed:", err)
		fmt.Println("      Tip: run as Administrator (binding UDP :68 may require elevation).")
		return
	}

	if len(servers) == 0 {
		fmt.Println("  [!] No DHCP offers detected")
		return
	}

	if len(servers) > 1 {
		fmt.Println(color.New(color.FgRed, color.Bold).Sprint("  [!] MULTIPLE DHCP SERVERS DETECTED"))
	}

	for _, s := range servers {
		fmt.Println("\n  Server:", s.ServerIP)
		fmt.Println("    Offers:", s.Offers)
		for _, ip := range s.Offered {
			fmt.Println("    Offered IP:", ip)
		}
		if s.Router != "" {
			fmt.Println("    Router:", s.Router)
		}
		if len(s.DNS) > 0 {
			fmt.Println("    DNS:", strings.Join(s.DNS, ", "))
		}
		if s.LeaseTime != "" {
			fmt.Println("    Lease:", s.LeaseTime)
		}
	}
}

func probeDHCP(iface *net.Interface, listenFor time.Duration) (map[string]*DHCPServer, error) {
	// Listen on DHCP client port 68 (admin often required on Windows).
	laddr := &net.UDPAddr{IP: net.IPv4zero, Port: 68}
	conn, err := net.ListenUDP("udp4", laddr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	_ = conn.SetReadBuffer(256 * 1024)
	_ = conn.SetWriteBuffer(64 * 1024)

	xidBytes := make([]byte, 4)
	if _, err := rand.Read(xidBytes); err != nil {
		return nil, err
	}
	xid := binary.BigEndian.Uint32(xidBytes)

	discover := buildDHCPDiscover(xid, iface.HardwareAddr)

	bcast := &net.UDPAddr{IP: net.IPv4bcast, Port: 67}
	// Send a couple times (helps on noisy networks)
	for i := 0; i < 2; i++ {
		_, _ = conn.WriteToUDP(discover, bcast)
		time.Sleep(150 * time.Millisecond)
	}

	servers := make(map[string]*DHCPServer)

	deadline := time.Now().Add(listenFor)
	_ = conn.SetReadDeadline(deadline)

	buf := make([]byte, 4096)
	for {
		n, raddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			var nerr net.Error
			if errors.As(err, &nerr) && nerr.Timeout() {
				break
			}
			return nil, err
		}

		pkt := buf[:n]
		offer, err := parseDHCPOffer(pkt)
		if err != nil {
			continue
		}
		if offer.XID != xid {
			continue
		}

		// Group by option 54 (Server Identifier). Fallback to UDP source IP.
		serverID := ""
		if offer.ServerID != nil && offer.ServerID.To4() != nil {
			serverID = offer.ServerID.String()
		} else if raddr != nil && raddr.IP != nil {
			serverID = raddr.IP.String()
		}
		if serverID == "" {
			continue
		}

		s, ok := servers[serverID]
		if !ok {
			s = &DHCPServer{ServerIP: serverID}
			servers[serverID] = s
		}
		s.Offers++

		if offer.YourIP != nil && offer.YourIP.To4() != nil {
			s.Offered = appendUnique(s.Offered, offer.YourIP.String())
		}
		if offer.Router != nil && offer.Router.To4() != nil && s.Router == "" {
			s.Router = offer.Router.String()
		}
		for _, d := range offer.DNS {
			if d != nil && d.To4() != nil {
				s.DNS = appendUnique(s.DNS, d.String())
			}
		}
		if offer.LeaseSeconds > 0 && s.LeaseTime == "" {
			d := time.Duration(offer.LeaseSeconds) * time.Second
			h := int(d.Hours())
			m := int(d.Minutes()) % 60
			s.LeaseTime = fmt.Sprintf("%dh %dm", h, m)
		}
	}

	return servers, nil
}

func appendUnique(list []string, v string) []string {
	for _, s := range list {
		if s == v {
			return list
		}
	}
	return append(list, v)
}

// ---- DHCP packet building/parsing (no external deps) ----

const (
	bootRequest = 1
	bootReply   = 2
	htypeEther  = 1
	hlenEther   = 6

	dhcpMagicCookie = 0x63825363

	optMsgType   = 53
	optParamReq  = 55
	optReqIP     = 50
	optServerID  = 54
	optSubnet    = 1
	optRouter    = 3
	optDNS       = 6
	optLeaseTime = 51
	optEnd       = 255

	msgDiscover = 1
	msgOffer    = 2
)

func buildDHCPDiscover(xid uint32, mac net.HardwareAddr) []byte {
	// BOOTP fixed header: 236 bytes
	h := make([]byte, 236)
	h[0] = bootRequest
	h[1] = htypeEther
	h[2] = hlenEther
	h[3] = 0 // hops
	binary.BigEndian.PutUint32(h[4:8], xid)
	binary.BigEndian.PutUint16(h[8:10], 0)     // secs
	binary.BigEndian.PutUint16(h[10:12], 0x80) // flags: broadcast
	// ciaddr/yiaddr/siaddr/giaddr = 0
	copy(h[28:34], mac) // chaddr starts at offset 28

	p := make([]byte, 0, 300)
	p = append(p, h...)

	// magic cookie
	c := make([]byte, 4)
	binary.BigEndian.PutUint32(c, dhcpMagicCookie)
	p = append(p, c...)

	// options
	// DHCP Message Type: Discover
	p = append(p, optMsgType, 1, msgDiscover)

	// Parameter Request List: subnet, router, dns, lease time, server id
	p = append(p, optParamReq, 5, optSubnet, optRouter, optDNS, optLeaseTime, optServerID)

	// (Optional) Requested IP (left out on purpose; pure DISCOVER)

	// End
	p = append(p, optEnd)

	return p
}

type dhcpOffer struct {
	XID          uint32
	YourIP       net.IP
	ServerID     net.IP
	Router       net.IP
	DNS          []net.IP
	LeaseSeconds uint32
}

func parseDHCPOffer(p []byte) (*dhcpOffer, error) {
	if len(p) < 240 {
		return nil, errors.New("short packet")
	}
	if p[0] != bootReply {
		return nil, errors.New("not boot reply")
	}

	xid := binary.BigEndian.Uint32(p[4:8])
	yiaddr := net.IPv4(p[16], p[17], p[18], p[19])

	if binary.BigEndian.Uint32(p[236:240]) != dhcpMagicCookie {
		return nil, errors.New("no magic cookie")
	}

	o := &dhcpOffer{XID: xid, YourIP: yiaddr}

	// options start at 240
	i := 240
	var msgType byte
	for i < len(p) {
		code := p[i]
		i++
		if code == optEnd {
			break
		}
		if code == 0 { // pad
			continue
		}
		if i >= len(p) {
			break
		}
		l := int(p[i])
		i++
		if i+l > len(p) {
			break
		}
		data := p[i : i+l]
		i += l

		switch code {
		case optMsgType:
			if len(data) == 1 {
				msgType = data[0]
			}
		case optServerID:
			if len(data) == 4 {
				o.ServerID = net.IPv4(data[0], data[1], data[2], data[3])
			}
		case optRouter:
			if len(data) >= 4 {
				o.Router = net.IPv4(data[0], data[1], data[2], data[3])
			}
		case optDNS:
			for j := 0; j+3 < len(data); j += 4 {
				o.DNS = append(o.DNS, net.IPv4(data[j], data[j+1], data[j+2], data[j+3]))
			}
		case optLeaseTime:
			if len(data) == 4 {
				o.LeaseSeconds = binary.BigEndian.Uint32(data)
			}
		}
	}

	if msgType != msgOffer {
		return nil, errors.New("not offer")
	}
	return o, nil
}
