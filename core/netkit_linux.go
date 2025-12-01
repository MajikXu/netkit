//go:build linux
// +build linux

package core

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type LinuxNetkit struct{}

func DefaultNetkit() Netkit {
	return NewLinuxNetkit()
}

func NewLinuxNetkit() *LinuxNetkit { return &LinuxNetkit{} }

func (p *LinuxNetkit) Hostname() (string, error) { return os.Hostname() }

func (p *LinuxNetkit) DNSServers() ([]string, error) {
	// No external commands; read resolv.conf directly
	return readResolvConfNameservers("/etc/resolv.conf"), nil
}

func (p *LinuxNetkit) LanInterfaces() ([]LanNetworkInterface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var lan []LanNetworkInterface
	for _, iface := range ifaces {
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
		lan = append(lan, LanNetworkInterface{Interface: ni})
	}
	return lan, nil
}

func (p *LinuxNetkit) WlanInterfaces() ([]WlanNetworkInterface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var wlan []WlanNetworkInterface
	for _, iface := range ifaces {
		if !p.isWireless(iface.Name) {
			continue
		}
		ni, err := p.buildNetworkInterface(iface)
		if err != nil {
			continue
		}
		wlan = append(wlan, WlanNetworkInterface{Interface: ni, Security: WlanSecurityUnknown})
	}
	return wlan, nil
}

func (p *LinuxNetkit) buildNetworkInterface(iface net.Interface) (NetworkInterface, error) {
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
	gateway := p.getDefaultGatewayFromProc(iface.Name)
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok {
			ip := ipNet.IP
			var t NetworkAddressType
			var maskStr string
			if ip.To4() != nil {
				t = NetworkAddressTypeV4
				maskStr = ipv4MaskString(ipNet.Mask)
			} else if ip.To16() != nil {
				t = NetworkAddressTypeV6
				ones, _ := ipNet.Mask.Size()
				maskStr = fmt.Sprintf("%d", ones)
			} else {
				continue
			}
			ni.Addresses = append(ni.Addresses, NetworkAddress{Type: t, Address: ip.String(), SubnetMask: maskStr, Gateway: gateway})
		}
	}
	// Minimal DHCP inference: presence of lease file in dhclient
	if p.hasDhcpLease(iface.Name) {
		ni.Mode = IpModeDHCP
	} else if len(ni.Addresses) > 0 {
		ni.Mode = IpModeStatic
	}
	return ni, nil
}

func (p *LinuxNetkit) isWireless(ifaceName string) bool {
	// Use sysfs presence without commands
	if _, err := os.Stat(filepath.Join("/sys/class/net", ifaceName, "wireless")); err == nil {
		return true
	}
	n := strings.ToLower(ifaceName)
	return strings.HasPrefix(n, "wl") || strings.HasPrefix(n, "wlan")
}

func (p *LinuxNetkit) getDefaultGatewayFromProc(ifaceName string) string {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	if !sc.Scan() {
		return ""
	} // skip header
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) >= 3 && fields[0] == ifaceName && fields[1] == "00000000" {
			return hexToIP(fields[2])
		}
	}
	return ""
}

func hexToIP(hex string) string {
	if len(hex) != 8 {
		return ""
	}
	var ip [4]byte
	for i := 0; i < 4; i++ {
		val, _ := strconv.ParseUint(hex[i*2:i*2+2], 16, 8)
		ip[3-i] = byte(val)
	}
	return fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])
}

func (p *LinuxNetkit) hasDhcpLease(ifaceName string) bool {
	// Common dhclient lease locations
	paths := []string{
		"/var/lib/dhcp/dhclient.leases",
		"/var/lib/dhcpcd/dhcpcd-%s.lease",
		"/var/lib/NetworkManager/internal-dhcp-%s.conf",
	}
	for _, tpl := range paths {
		path := tpl
		if strings.Contains(tpl, "%s") {
			path = fmt.Sprintf(tpl, ifaceName)
		}
		if _, err := os.Stat(path); err == nil {
			return true
		}
	}
	return false
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
