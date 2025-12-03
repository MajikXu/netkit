//go:build linux
// +build linux

package core

// linux backend now implemented without cgo; legacy helpers removed

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"

	"github.com/ebitengine/purego"
)

type LinuxNetkit struct{}

const accessFOK = 0

var (
	libcOnce   sync.Once
	libcErr    error
	libcHandle uintptr

	libcAccess func(*byte, int32) int32
)

func ensureLibc() error {
	libcOnce.Do(func() {
		const flags = purego.RTLD_LAZY | purego.RTLD_LOCAL
		var lastErr error
		for _, name := range []string{"libc.so.6", "libc.so"} {
			handle, err := purego.Dlopen(name, flags)
			if err != nil {
				lastErr = err
				continue
			}
			libcHandle = handle
			break
		}
		if libcHandle == 0 {
			libcErr = fmt.Errorf("libc load failed: %w", lastErr)
			return
		}
		sym, err := purego.Dlsym(libcHandle, "access")
		if err != nil || sym == 0 {
			if err == nil {
				err = fmt.Errorf("symbol access not found")
			}
			purego.Dlclose(libcHandle)
			libcHandle = 0
			libcErr = err
			return
		}
		purego.RegisterFunc(&libcAccess, sym)
		libcErr = nil
	})
	return libcErr
}

func DefaultNetkit() Netkit {
	return NewLinuxNetkit()
}

func NewLinuxNetkit() *LinuxNetkit { return &LinuxNetkit{} }

func (p *LinuxNetkit) Hostname() (string, error) { return os.Hostname() }

func (p *LinuxNetkit) DNSServers() ([]string, error) {
	servers := getLinuxDNSServers("/etc/resolv.conf")
	if len(servers) > 0 {
		return servers, nil
	}
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
	if ifaceName == "" {
		return false
	}
	path := "/sys/class/net/" + ifaceName + "/wireless"
	if checkPathExists(path) {
		return true
	}
	lower := strings.ToLower(ifaceName)
	if strings.HasPrefix(lower, "wl") {
		return true
	}
	if strings.HasPrefix(lower, "wlan") {
		return true
	}
	return false
}

func (p *LinuxNetkit) getDefaultGatewayFromProc(ifaceName string) string {
	file, err := os.Open("/proc/net/route")
	if err != nil {
		return ""
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	if !scanner.Scan() {
		return ""
	}
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 {
			continue
		}
		if fields[0] != ifaceName {
			continue
		}
		dest, err := strconv.ParseUint(fields[1], 16, 32)
		if err != nil || dest != 0 {
			continue
		}
		gatewayVal, err := strconv.ParseUint(fields[2], 16, 32)
		if err != nil {
			continue
		}
		b0 := byte(gatewayVal & 0xFF)
		b1 := byte((gatewayVal >> 8) & 0xFF)
		b2 := byte((gatewayVal >> 16) & 0xFF)
		b3 := byte((gatewayVal >> 24) & 0xFF)
		return fmt.Sprintf("%d.%d.%d.%d", b0, b1, b2, b3)
	}
	return ""
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

func checkPathExists(path string) bool {
	if path == "" {
		return false
	}
	if err := ensureLibc(); err == nil && libcAccess != nil {
		buf := append([]byte(path), 0)
		if len(buf) > 0 {
			if libcAccess((*byte)(&buf[0]), accessFOK) == 0 {
				runtime.KeepAlive(buf)
				return true
			}
			runtime.KeepAlive(buf)
		}
	}
	_, err := os.Stat(path)
	return err == nil
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

func getLinuxDNSServers(path string) []string {
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()

	var servers []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		value := fields[1]
		if strings.HasPrefix(value, "#") {
			continue
		}
		servers = append(servers, value)
	}
	return servers
}
