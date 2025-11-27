//go:build darwin

package core

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

type DarwinNetkit struct{}

func DefaultNetkit() Netkit {
	return NewDarwinNetkit()
}

func NewDarwinNetkit() *DarwinNetkit {
	return &DarwinNetkit{}
}

func (p *DarwinNetkit) Hostname() (string, error) {
	return os.Hostname()
}

func (p *DarwinNetkit) DNSServers() ([]string, error) {
	// Try scutil first (more reliable on macOS)
	cmd := exec.Command("scutil", "--dns")
	output, err := cmd.Output()
	if err == nil {
		servers := parseDNSFromScutil(string(output))
		if len(servers) > 0 {
			return servers, nil
		}
	}

	// Fallback to resolv.conf
	return readResolvConfNameservers("/etc/resolv.conf"), nil
}

func parseDNSFromScutil(output string) []string {
	var servers []string
	seen := make(map[string]bool)
	re := regexp.MustCompile(`nameserver\[\d+\]\s*:\s*(\S+)`)
	matches := re.FindAllStringSubmatch(output, -1)
	for _, match := range matches {
		if len(match) > 1 {
			server := match[1]
			if !seen[server] {
				servers = append(servers, server)
				seen[server] = true
			}
		}
	}
	return servers
}

func (p *DarwinNetkit) LanInterfaces() ([]LanNetworkInterface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var lanIfaces []LanNetworkInterface
	for _, iface := range ifaces {
		// Skip loopback and wireless interfaces
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if isWirelessInterface(iface.Name) {
			continue
		}

		ni, err := p.buildNetworkInterface(iface)
		if err != nil {
			continue
		}

		lanIfaces = append(lanIfaces, LanNetworkInterface{Interface: ni})
	}

	return lanIfaces, nil
}

func (p *DarwinNetkit) WlanInterfaces() ([]WlanNetworkInterface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var wlanIfaces []WlanNetworkInterface
	for _, iface := range ifaces {
		if !isWirelessInterface(iface.Name) {
			continue
		}

		ni, err := p.buildNetworkInterface(iface)
		if err != nil {
			continue
		}

		wlan := WlanNetworkInterface{
			Interface: ni,
			Security:  WlanSecurityUnknown,
		}

		// Get Wi-Fi specific info using airport utility
		wifiInfo := p.getWiFiInfo(iface.Name)
		if ssid, ok := wifiInfo["SSID"]; ok && ssid != "" {
			wlan.SSID = ssid
		}
		if channel, ok := wifiInfo["Channel"]; ok {
			if ch, err := strconv.Atoi(channel); err == nil {
				wlan.Channel = int32(ch)
			}
		}
		if rssi, ok := wifiInfo["RSSI"]; ok {
			if r, err := strconv.Atoi(rssi); err == nil {
				wlan.SignalStrengthUnfiltered = int32(r)
				wlan.SignalStrength = rssiToSignalStrength(int32(r))
			}
		}
		if security, ok := wifiInfo["Security"]; ok {
			wlan.Security = parseWiFiSecurity(security)
		}
		if txRate, ok := wifiInfo["TransmitRate"]; ok {
			if rate, err := strconv.Atoi(txRate); err == nil {
				wlan.LinkSpeedTx = int32(rate)
			}
		}

		wlanIfaces = append(wlanIfaces, wlan)
	}

	return wlanIfaces, nil
}

func (p *DarwinNetkit) buildNetworkInterface(iface net.Interface) (NetworkInterface, error) {
	ni := NetworkInterface{
		Device: iface.Name,
		Mac:    iface.HardwareAddr.String(),
		Mode:   IpModeNone,
		ConnectionStatus: func() ConnectionStatus {
			if iface.Flags&net.FlagUp != 0 {
				return ConnectionStatusConnected
			}
			return ConnectionStatusUnconnected
		}(),
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return ni, err
	}

	gateway := p.getDefaultGateway(iface.Name)

	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok {
			ip := ipNet.IP
			var addrType NetworkAddressType
			var maskStr string

			if ip.To4() != nil {
				addrType = NetworkAddressTypeV4
				maskStr = ipv4MaskString(ipNet.Mask)
			} else if ip.To16() != nil {
				addrType = NetworkAddressTypeV6
				ones, _ := ipNet.Mask.Size()
				maskStr = fmt.Sprintf("%d", ones)
			} else {
				continue
			}

			ni.Addresses = append(ni.Addresses, NetworkAddress{
				Type:       addrType,
				Address:    ip.String(),
				SubnetMask: maskStr,
				Gateway:    gateway,
			})
		}
	}

	// Try to determine DHCP vs Static
	if p.isDHCP(iface.Name) {
		ni.Mode = IpModeDHCP
	} else if len(ni.Addresses) > 0 {
		ni.Mode = IpModeStatic
	}

	return ni, nil
}

func (p *DarwinNetkit) getDefaultGateway(ifaceName string) string {
	cmd := exec.Command("netstat", "-rn", "-f", "inet")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}

	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) >= 6 && fields[0] == "default" {
			if fields[5] == ifaceName {
				return fields[1]
			}
		}
	}
	return ""
}

func (p *DarwinNetkit) isDHCP(ifaceName string) bool {
	cmd := exec.Command("ipconfig", "getpacket", ifaceName)
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(output), "lease_time")
}

func (p *DarwinNetkit) getWiFiInfo(ifaceName string) map[string]string {
	info := make(map[string]string)

	// Try ipconfig getsummary first (most reliable, shows actual SSID)
	cmd := exec.Command("ipconfig", "getsummary", ifaceName)
	output, err := cmd.Output()
	if err == nil {
		scanner := bufio.NewScanner(bytes.NewReader(output))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])

				switch key {
				case "SSID":
					info["SSID"] = value
				case "Security":
					info["Security"] = value
				case "BSSID":
					info["BSSID"] = value
				}
			}
		}
	}

	// Try airport utility as fallback for additional info
	cmd = exec.Command("/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport", "-I")
	output, err = cmd.Output()
	if err == nil {
		scanner := bufio.NewScanner(bytes.NewReader(output))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])

				switch key {
				case "SSID":
					if _, ok := info["SSID"]; !ok {
						info["SSID"] = value
					}
				case "agrCtlRSSI":
					info["RSSI"] = value
				case "channel":
					info["Channel"] = value
				case "link auth":
					if _, ok := info["Security"]; !ok {
						info["Security"] = value
					}
				}
			}
		}
	}

	// Get additional info from system_profiler (channel, signal, etc.)
	if _, hasChannel := info["Channel"]; !hasChannel || info["RSSI"] == "" {
		cmd = exec.Command("system_profiler", "SPAirPortDataType")
		output, err = cmd.Output()
		if err == nil {
			p.parseSystemProfilerForDetails(string(output), ifaceName, info)
		}
	}

	return info
}

func (p *DarwinNetkit) parseSystemProfilerForDetails(output, ifaceName string, info map[string]string) {
	lines := strings.Split(output, "\n")
	inInterface := false
	inCurrentNetwork := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Check if we're in the right interface section
		if strings.Contains(trimmed, ifaceName+":") {
			inInterface = true
			continue
		}

		// Exit interface section when we hit another interface
		if inInterface && strings.HasSuffix(trimmed, ":") && (strings.Contains(trimmed, "en") || strings.Contains(trimmed, "wlan")) && !strings.Contains(trimmed, "Network") {
			break
		}

		if inInterface {
			if strings.Contains(trimmed, "Current Network Information:") {
				inCurrentNetwork = true
			}

			if inCurrentNetwork {
				parts := strings.SplitN(trimmed, ":", 2)
				if len(parts) == 2 {
					key := strings.TrimSpace(parts[0])
					value := strings.TrimSpace(parts[1])

					switch key {
					case "Channel":
						if _, ok := info["Channel"]; !ok {
							// Parse "60 (5GHz, 40MHz)" to get channel number
							channelParts := strings.Fields(value)
							if len(channelParts) > 0 {
								info["Channel"] = channelParts[0]
							}
						}
					case "Signal / Noise":
						if _, ok := info["RSSI"]; !ok {
							// Parse "-67 dBm / -97 dBm"
							signalParts := strings.Split(value, "/")
							if len(signalParts) > 0 {
								signalStr := strings.TrimSpace(signalParts[0])
								signalStr = strings.TrimSuffix(signalStr, " dBm")
								info["RSSI"] = signalStr
							}
						}
					case "Transmit Rate":
						if _, ok := info["TransmitRate"]; !ok {
							info["TransmitRate"] = value
						}
					}
				}
			}
		}
	}
}

func isWirelessInterface(name string) bool {
	// macOS typically uses en0 or en1 for Wi-Fi, but check with system
	name = strings.ToLower(name)
	return strings.HasPrefix(name, "en") && (name == "en0" || name == "en1")
}

func parseWiFiSecurity(security string) WlanSecurity {
	security = strings.ToLower(security)

	// Handle ipconfig getsummary format (e.g., "FT_8021X", "WPA2_PSK")
	if strings.Contains(security, "8021x") || strings.Contains(security, "ft_8021x") {
		return WlanSecurityWPA2EAP
	}

	if strings.Contains(security, "wpa3") {
		if strings.Contains(security, "sae") {
			return WlanSecurityWPA3SAE
		}
		return WlanSecurityWPA3EAP
	}
	if strings.Contains(security, "wpa2") {
		if strings.Contains(security, "eap") || strings.Contains(security, "enterprise") {
			return WlanSecurityWPA2EAP
		}
		return WlanSecurityWPA2
	}
	if strings.Contains(security, "wpa") {
		if strings.Contains(security, "eap") || strings.Contains(security, "enterprise") {
			return WlanSecurityWPAEAP
		}
		return WlanSecurityWPA
	}
	if strings.Contains(security, "wep") {
		return WlanSecurityWEP
	}
	if strings.Contains(security, "open") || strings.Contains(security, "none") {
		return WlanSecurityOpen
	}
	return WlanSecurityUnknown
}

func rssiToSignalStrength(rssi int32) SignalStrength {
	if rssi >= -50 {
		return SignalStrengthExcellent
	} else if rssi >= -60 {
		return SignalStrengthGood
	} else if rssi >= -70 {
		return SignalStrengthFair
	} else if rssi >= -80 {
		return SignalStrengthWeak
	}
	return SignalStrengthPoor
}

func ipv4MaskString(m net.IPMask) string {
	if len(m) == 4 {
		return fmt.Sprintf("%d.%d.%d.%d", m[0], m[1], m[2], m[3])
	}
	return ""
}

func readResolvConfNameservers(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var ns []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "nameserver") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				ns = append(ns, parts[1])
			}
		}
	}
	return ns
}
