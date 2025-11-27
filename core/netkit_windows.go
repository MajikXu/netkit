//go:build windows

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

type WindowsNetkit struct{}

func DefaultNetkit() Netkit {
	return NewWindowsNetkit()
}

func NewWindowsNetkit() *WindowsNetkit {
	return &WindowsNetkit{}
}

// runPowerShell executes a PowerShell command with English output
func (p *WindowsNetkit) runPowerShell(command string) ([]byte, error) {
	cmd := exec.Command("powershell", "-Command", "Set-WinUILanguageOverride -Language en-US; "+command)
	return cmd.Output()
}

func (p *WindowsNetkit) Hostname() (string, error) {
	return os.Hostname()
}

func (p *WindowsNetkit) DNSServers() ([]string, error) {
	output, err := p.runPowerShell("Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object -ExpandProperty ServerAddresses")
	if err != nil {
		// Fallback to ipconfig
		return p.getDNSFromIpconfig(), nil
	}

	var servers []string
	seen := make(map[string]bool)
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !seen[line] {
			servers = append(servers, line)
			seen[line] = true
		}
	}

	return servers, nil
}

func (p *WindowsNetkit) getDNSFromIpconfig() []string {
	cmd := exec.Command("ipconfig", "/all")
	output, err := cmd.Output()
	if err != nil {
		return nil
	}

	var servers []string
	seen := make(map[string]bool)
	re := regexp.MustCompile(`DNS Servers.*?:\s*(\d+\.\d+\.\d+\.\d+)`)
	matches := re.FindAllStringSubmatch(string(output), -1)
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

func (p *WindowsNetkit) LanInterfaces() ([]LanNetworkInterface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var lanIfaces []LanNetworkInterface
	for _, iface := range ifaces {
		// Skip loopback and wireless
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if p.isWireless(iface.Name) {
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

func (p *WindowsNetkit) WlanInterfaces() ([]WlanNetworkInterface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	// Get WLAN interface info from netsh
	wlanInfoMap := p.getWlanInterfaceInfo()

	var wlanIfaces []WlanNetworkInterface
	for _, iface := range ifaces {
		if !p.isWireless(iface.Name) {
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

		// Populate WiFi-specific info
		if info, ok := wlanInfoMap[iface.Name]; ok {
			p.populateWiFiInfo(&wlan, info)
		}

		wlanIfaces = append(wlanIfaces, wlan)
	}

	return wlanIfaces, nil
}

func (p *WindowsNetkit) buildNetworkInterface(iface net.Interface) (NetworkInterface, error) {
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

	// Check if using DHCP
	if p.isDHCP(iface.Name) {
		ni.Mode = IpModeDHCP
	} else if len(ni.Addresses) > 0 {
		ni.Mode = IpModeStatic
	}

	return ni, nil
}

func (p *WindowsNetkit) isWireless(ifaceName string) bool {
	// Use netsh to check if interface is wireless
	output, err := p.runPowerShell("netsh wlan show interfaces")
	if err != nil {
		return false
	}

	// Check if interface name appears in WLAN interfaces
	return strings.Contains(string(output), ifaceName)
}

func (p *WindowsNetkit) getDefaultGateway(ifaceName string) string {
	output, err := p.runPowerShell(
		fmt.Sprintf("Get-NetRoute -InterfaceAlias '%s' -DestinationPrefix 0.0.0.0/0 | Select-Object -ExpandProperty NextHop", ifaceName))
	if err != nil {
		return p.getGatewayFromRoute(ifaceName)
	}

	gateway := strings.TrimSpace(string(output))
	if gateway != "" && gateway != "0.0.0.0" {
		return gateway
	}

	return p.getGatewayFromRoute(ifaceName)
}

func (p *WindowsNetkit) getGatewayFromRoute(ifaceName string) string {
	cmd := exec.Command("route", "print", "0.0.0.0")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}

	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "0.0.0.0") {
			fields := strings.Fields(line)
			if len(fields) >= 3 {
				return fields[2]
			}
		}
	}

	return ""
}

func (p *WindowsNetkit) isDHCP(ifaceName string) bool {
	output, err := p.runPowerShell(
		fmt.Sprintf("(Get-NetIPInterface -InterfaceAlias '%s' -AddressFamily IPv4).Dhcp", ifaceName))
	if err != nil {
		return false
	}

	dhcp := strings.TrimSpace(string(output))
	return strings.EqualFold(dhcp, "Enabled") || strings.EqualFold(dhcp, "True")
}

func (p *WindowsNetkit) getWlanInterfaceInfo() map[string]map[string]string {
	output, err := p.runPowerShell("netsh wlan show interfaces")
	if err != nil {
		return nil
	}

	result := make(map[string]map[string]string)
	var currentInterface string
	var currentInfo map[string]string

	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "" {
			if currentInterface != "" && currentInfo != nil {
				result[currentInterface] = currentInfo
				currentInterface = ""
				currentInfo = nil
			}
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		if key == "Name" {
			currentInterface = value
			currentInfo = make(map[string]string)
		} else if currentInfo != nil {
			currentInfo[key] = value
		}
	}

	// Add last interface
	if currentInterface != "" && currentInfo != nil {
		result[currentInterface] = currentInfo
	}

	return result
}

func (p *WindowsNetkit) populateWiFiInfo(wlan *WlanNetworkInterface, info map[string]string) {
	if ssid, ok := info["SSID"]; ok {
		wlan.SSID = ssid
	}
	if channel, ok := info["Channel"]; ok {
		if ch, err := strconv.Atoi(channel); err == nil {
			wlan.Channel = int32(ch)
		}
	}
	if signal, ok := info["Signal"]; ok {
		// Signal is typically in percentage format like "85%"
		signal = strings.TrimSuffix(signal, "%")
		if percentage, err := strconv.Atoi(signal); err == nil {
			// Convert percentage to approximate RSSI
			// 100% ≈ -30dBm, 0% ≈ -100dBm
			rssi := -100 + (percentage * 70 / 100)
			wlan.SignalStrengthUnfiltered = int32(rssi)
			wlan.SignalStrength = rssiToSignalStrength(int32(rssi))
		}
	}
	if auth, ok := info["Authentication"]; ok {
		wlan.Security = parseWindowsWiFiSecurity(auth)
	}
	if rxRate, ok := info["Receive rate (Mbps)"]; ok {
		if rate, err := strconv.ParseFloat(rxRate, 32); err == nil {
			wlan.LinkSpeedTx = int32(rate)
		}
	}
	if txRate, ok := info["Transmit rate (Mbps)"]; ok {
		if rate, err := strconv.ParseFloat(txRate, 32); err == nil {
			wlan.LinkSpeedTx = int32(rate)
		}
	}
	if radioType, ok := info["Radio type"]; ok {
		// Parse frequency from radio type (e.g., "802.11ac" -> 5GHz)
		if strings.Contains(radioType, "802.11a") || strings.Contains(radioType, "802.11ac") ||
			strings.Contains(radioType, "802.11ax") && strings.Contains(radioType, "5") {
			wlan.Frequency = 5000
		} else {
			wlan.Frequency = 2400
		}
	}
}

func parseWindowsWiFiSecurity(auth string) WlanSecurity {
	auth = strings.ToLower(auth)
	if strings.Contains(auth, "wpa3") {
		if strings.Contains(auth, "sae") {
			return WlanSecurityWPA3SAE
		}
		return WlanSecurityWPA3EAP
	}
	if strings.Contains(auth, "wpa2") {
		if strings.Contains(auth, "enterprise") || strings.Contains(auth, "eap") {
			return WlanSecurityWPA2EAP
		}
		return WlanSecurityWPA2
	}
	if strings.Contains(auth, "wpa") {
		if strings.Contains(auth, "enterprise") || strings.Contains(auth, "eap") {
			return WlanSecurityWPAEAP
		}
		return WlanSecurityWPA
	}
	if strings.Contains(auth, "wep") {
		return WlanSecurityWEP
	}
	if strings.Contains(auth, "open") {
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
