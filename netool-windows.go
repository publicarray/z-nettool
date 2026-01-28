//go:build windows

package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
	"unicode/utf16"
	"unsafe"

	"github.com/fatih/color"
	"golang.org/x/sys/windows"
)

const (
	DHCPCaptureTime = 3  // seconds to listen for DHCP offers
	LLDPCaptureTime = 33 // seconds to listen for LLDP
	PktmonFile      = "PktMon-lldp.etl"
	PktmonTxt       = "PktMon-lldp.txt"
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
	printLLDP(*ifaceName)
	printConnectivity()
	printDHCP(*ifaceName)

	os.Remove(PktmonFile)
	os.Remove(PktmonTxt)
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

	link := getLinkSpeed(ifaceName)

	fmt.Println("\nInterface:")
	fmt.Println("  Name:", ifaceName)
	fmt.Println("  MAC: ", iface.HardwareAddr)
	fmt.Println("  IPv4:", ipv4)
	fmt.Println("  IPv6:", ipv6)
	fmt.Println("  Link:", link)
}

func getLinkSpeed(ifaceName string) string {
	adapters, err := getAdapters()
	if err != nil {
		panic(err)
	}
	link := "Unknown"
	for _, a := range adapters {
		if a.OperStatus != windows.IfOperStatusUp {
			continue
		}

		speedName := classifySpeed(a.ReceiveLinkSpeed)
		if ifaceName == windows.UTF16PtrToString(a.FriendlyName) {
			link = speedName
		}

		fmt.Printf("Adapter: %s\n", windows.UTF16PtrToString(a.FriendlyName))
		fmt.Printf("  Speed RX: %.2f Gbps\n", float64(a.ReceiveLinkSpeed)/1e9)
		fmt.Printf("  Speed TX: %.2f Gbps\n", float64(a.TransmitLinkSpeed)/1e9)
		fmt.Printf("  Type: %s\n", speedName)
	}
	return link
}

func getAdapters() ([]*windows.IpAdapterAddresses, error) {
	var size uint32
	err := windows.GetAdaptersAddresses(
		windows.AF_UNSPEC,
		windows.GAA_FLAG_INCLUDE_PREFIX,
		0,
		nil,
		&size,
	)
	if err != windows.ERROR_BUFFER_OVERFLOW {
		return nil, err
	}

	buf := make([]byte, size)
	addr := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))

	err = windows.GetAdaptersAddresses(
		windows.AF_UNSPEC,
		windows.GAA_FLAG_INCLUDE_PREFIX,
		0,
		addr,
		&size,
	)
	if err != nil {
		return nil, err
	}

	var list []*windows.IpAdapterAddresses
	for a := addr; a != nil; a = a.Next {
		list = append(list, a)
	}
	return list, nil
}

func classifySpeed(bps uint64) string {
	switch {
	case bps >= 40_000_000_000:
		return "40GbE"
	case bps >= 25_000_000_000:
		return "25GbE"
	case bps >= 10_000_000_000:
		return "10GbE"
	case bps >= 2_500_000_000:
		return "2.5GbE"
	case bps >= 1_000_000_000:
		return "GbE"
	case bps >= 100_000_000:
		return "Fast Ethernet (FE)"
	case bps >= 10_000_000:
		return "Ethernet (E)"
	default:
		return "Unknown"
	}
}

type LLDPInfo struct {
	ChassisID         string
	PortID            string
	TTL               uint16
	PortDescription   string
	SystemDescription string
	SystemName        string
	VLAN              int
}

var hexLineRegex = regexp.MustCompile(`0x[0-9a-fA-F]{4}:\s+((?:[0-9a-fA-F]{4}\s*)+)`)

// Transform UTF16 to UTF8 because Windows PktMon logs are often UTF16
func DecodeUTF16(data []byte) (string, error) {
	if len(data) < 2 {
		return string(data), nil
	}
	// Check for BOM or just try to decode
	u16s := make([]uint16, len(data)/2)
	err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &u16s)
	if err != nil {
		return "", err
	}
	return string(utf16.Decode(u16s)), nil
}

func printLLDP(iface string) {
	fmt.Println("\nSwitch / VLAN Info (LLDP)")

	// Stop previous capture if exists
	exec.Command("pktmon", "stop").Run()
	os.Remove(PktmonFile)
	os.Remove(PktmonTxt)

	// Start capture
	start := exec.Command("pktmon", "start", "--capture", "--pkt-size", "1600", "--etw", "-f", "ethernet.type==0x88cc", "--file-name", PktmonFile)
	if err := start.Run(); err != nil {
		fmt.Println("  [!] Failed to start pktmon. Are you running as Admin?", err)
		return
	}

	// Channel to signal the progress indicator to stop
	done := make(chan bool)
	go showProgress(LLDPCaptureTime, done)

	// Wait for the capture window
	time.Sleep(LLDPCaptureTime * time.Second)

	// Stop capture and stop the spinner
	exec.Command("pktmon", "stop").Run()
	done <- true
	fmt.Println("")

	// Convert ETL to Text
	exec.Command("pktmon", "etl2txt", PktmonFile, "--hex", "--out", PktmonTxt).Run()

	parseLLDPFromTxt(PktmonTxt)
}

// showProgress creates a terminal spinner and countdown
func showProgress(seconds int, done chan bool) {
	chars := []string{"|", "/", "-", "\\"}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	startTime := time.Now()
	i := 0
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			elapsed := int(time.Since(startTime).Seconds())
			remaining := seconds - elapsed
			if remaining < 0 {
				remaining = 0
			}
			// \r returns the cursor to the start of the line
			fmt.Printf("\r  [%s] Listening for LLDP packets... %ds remaining ", chars[i%len(chars)], remaining)
			i++
		}
	}
}
func parseLLDPFromTxt(path string) {
	rawBytes, err := os.ReadFile(path)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	content := ""
	if len(rawBytes) > 2 && (rawBytes[1] == 0x00 || rawBytes[0] == 0xFF) {
		content, _ = DecodeUTF16(rawBytes)
	} else {
		content = string(rawBytes)
	}

	var currentHex strings.Builder
	scanner := bufio.NewScanner(strings.NewReader(content))

	// Use a map to deduplicate results
	seenPackets := make(map[string]bool)

	fmt.Printf("%-30s | %-10s | %-6s | %-15s | %s\n", "System Name", "Port", "VLAN", "Chassis ID", "Description")
	fmt.Println(strings.Repeat("-", 90))

	for scanner.Scan() {
		line := scanner.Text()

		if strings.Contains(line, "PktGroupId") {
			if currentHex.Len() > 0 {
				displayLLDP(currentHex.String(), seenPackets)
				currentHex.Reset()
			}
		}

		if strings.Contains(line, "0x") && strings.Contains(line, ":") {
			parts := strings.Split(line, ":")
			if len(parts) > 1 {
				currentHex.WriteString(cleanHexChars(parts[1]))
			}
		}
	}
	if currentHex.Len() > 0 {
		displayLLDP(currentHex.String(), seenPackets)
	}
}

func displayLLDP(rawHex string, seen map[string]bool) {
	fullHex := strings.ToLower(rawHex)
	idx := strings.Index(fullHex, "88cc")
	if idx == -1 {
		return
	}

	payload := fullHex[idx+4:]
	info, err := ParseLLDPHex(payload)
	if err != nil || info == nil || info.SystemName == "" {
		return
	}

	// Create a unique key for deduplication
	key := fmt.Sprintf("%s-%s-%s", info.ChassisID, info.PortID, info.SystemName)
	if seen[key] {
		return
	}
	seen[key] = true

	vlanStr := "N/A"
	if info.VLAN != -1 {
		vlanStr = fmt.Sprintf("%d", info.VLAN)
	}

	// Trim long descriptions for the CLI table
	desc := info.SystemDescription
	if len(desc) > 30 {
		desc = desc[:27] + "..."
	}

	fmt.Printf("%-30s | %-10s | %-6s | %-15s | %s\n",
		info.SystemName, info.PortDescription, vlanStr, info.ChassisID, desc)
}

func cleanHexChars(input string) string {
	return strings.Map(func(r rune) rune {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F') {
			return r
		}
		return -1
	}, input)
}

func processRawHex(fullHex string) {
	fullHex = strings.ToLower(fullHex)

	// 3. Look for the LLDP EtherType (88cc)
	idx := strings.Index(fullHex, "88cc")
	if idx == -1 {
		// Log this for debugging but keep it quiet for non-LLDP packets
		return
	}

	fmt.Printf("[DEBUG] Found LLDP marker (88cc) at index %d. Extracting payload...\n", idx)

	// Payload starts after the 4 characters of "88cc"
	payload := fullHex[idx+4:]
	info, err := ParseLLDPHex(payload)

	if err != nil {
		fmt.Printf("[DEBUG] Parse error: %v\n", err)
		return
	}

	if info != nil && (info.SystemName != "" || info.ChassisID != "") {
		vlanStr := "N/A"
		if info.VLAN != -1 {
			vlanStr = fmt.Sprintf("%d", info.VLAN)
		}
		fmt.Printf("%-20s | %-15s | %-15s | %s\n",
			info.SystemName, info.PortDescription, vlanStr, info.ChassisID)
	} else {
		fmt.Println("[DEBUG] Packet parsed but contained no System Name or Chassis ID.")
	}
}

func ParseLLDPHex(hexStr string) (*LLDPInfo, error) {
	data, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, err
	}

	// Added SystemDescription to your existing LLDPInfo struct
	type ExtendedInfo struct {
		LLDPInfo
		SystemDescription string
	}

	info := &ExtendedInfo{}
	info.VLAN = -1
	offset := 0

	for offset+2 <= len(data) {
		header := binary.BigEndian.Uint16(data[offset : offset+2])
		tlvType := int(header >> 9)
		tlvLen := int(header & 0x01FF)
		offset += 2

		if tlvType == 0 || offset+tlvLen > len(data) {
			break
		}

		val := data[offset : offset+tlvLen]
		switch tlvType {
		case 1: // Chassis ID
			info.ChassisID = hex.EncodeToString(val[1:])
		case 2: // Port ID
			info.PortID = hex.EncodeToString(val[1:])
		case 4: // Port Description
			info.PortDescription = strings.TrimSpace(string(val))
		case 5: // System Name
			info.SystemName = strings.TrimSpace(string(val))
		case 6: // System Description
			info.SystemDescription = strings.TrimSpace(string(val))
		case 127: // VLAN
			if len(val) >= 6 && hex.EncodeToString(val[:3]) == "0080c2" && val[3] == 0x01 {
				info.VLAN = int(binary.BigEndian.Uint16(val[4:6]))
			}
		}
		offset += tlvLen
	}
	return &info.LLDPInfo, nil
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

	servers, err := probeDHCP(iface, time.Duration(DHCPCaptureTime)*time.Second)
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
	for i := 0; i < 1; i++ {
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
