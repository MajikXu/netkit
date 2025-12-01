//go:build linux
// +build linux

package core

/*
#define _GNU_SOURCE
#include <ctype.h>
#include <limits.h>
#include <net/if.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

typedef struct {
	char **items;
	size_t count;
} LinuxStringList;

static void free_linux_string_list(LinuxStringList *list) {
	if (!list || !list->items) {
		return;
	}
	for (size_t i = 0; i < list->count; i++) {
		free(list->items[i]);
	}
	free(list->items);
	list->items = NULL;
	list->count = 0;
}

LinuxStringList CopyLinuxDNSServers(const char *path) {
	LinuxStringList list = {0};
	if (!path) {
		return list;
	}
	FILE *fp = fopen(path, "r");
	if (!fp) {
		return list;
	}
	char *line = NULL;
	size_t lineCap = 0;
	size_t capacity = 0;
	while (getline(&line, &lineCap, fp) != -1) {
		char *cursor = line;
		while (*cursor && isspace((unsigned char)*cursor)) {
			cursor++;
		}
		if (strncmp(cursor, "nameserver", 10) != 0 || (cursor[10] && !isspace((unsigned char)cursor[10]))) {
			continue;
		}
		cursor += 10;
		while (*cursor && isspace((unsigned char)*cursor)) {
			cursor++;
		}
		if (*cursor == '\0' || *cursor == '#') {
			continue;
		}
		char *end = cursor;
		while (*end && !isspace((unsigned char)*end)) {
			end++;
		}
		size_t length = (size_t)(end - cursor);
		if (length == 0) {
			continue;
		}
		char *value = (char *)malloc(length + 1);
		if (!value) {
			free_linux_string_list(&list);
			break;
		}
		memcpy(value, cursor, length);
		value[length] = '\0';
		if (list.count == capacity) {
			size_t newCapacity = capacity ? capacity * 2 : 4;
			char **tmp = (char **)realloc(list.items, newCapacity * sizeof(char *));
			if (!tmp) {
				free(value);
				free_linux_string_list(&list);
				break;
			}
			list.items = tmp;
			capacity = newCapacity;
		}
		list.items[list.count++] = value;
	}
	if (line) {
		free(line);
	}
	fclose(fp);
	return list;
}

void FreeLinuxStringList(LinuxStringList list) {
	LinuxStringList temp = list;
	free_linux_string_list(&temp);
}

char *CopyLinuxDefaultGateway(const char *iface) {
	if (!iface) {
		return NULL;
	}
	FILE *fp = fopen("/proc/net/route", "r");
	if (!fp) {
		return NULL;
	}
	char buffer[256];
	if (!fgets(buffer, sizeof(buffer), fp)) {
		fclose(fp);
		return NULL;
	}
	while (fgets(buffer, sizeof(buffer), fp)) {
		char dev[IFNAMSIZ] = {0};
		unsigned long dest = 0;
		unsigned long gateway = 0;
		int fields = sscanf(buffer, "%63s %lx %lx", dev, &dest, &gateway);
		if (fields < 3) {
			continue;
		}
		if (strcmp(dev, iface) != 0 || dest != 0) {
			continue;
		}
		char *result = (char *)malloc(16);
		if (!result) {
			break;
		}
		unsigned char bytes[4];
		bytes[0] = (unsigned char)(gateway & 0xFF);
		bytes[1] = (unsigned char)((gateway >> 8) & 0xFF);
		bytes[2] = (unsigned char)((gateway >> 16) & 0xFF);
		bytes[3] = (unsigned char)((gateway >> 24) & 0xFF);
		snprintf(result, 16, "%u.%u.%u.%u", bytes[0], bytes[1], bytes[2], bytes[3]);
		fclose(fp);
		return result;
	}
	fclose(fp);
	return NULL;
}

int LinuxIsWireless(const char *iface) {
	if (!iface || iface[0] == '\0') {
		return 0;
	}
	char path[PATH_MAX];
	if (snprintf(path, sizeof(path), "/sys/class/net/%s/wireless", iface) > 0) {
		struct stat st;
		if (stat(path, &st) == 0) {
			return 1;
		}
	}
	char lower[IFNAMSIZ];
	size_t len = strnlen(iface, IFNAMSIZ - 1);
	for (size_t i = 0; i < len; i++) {
		lower[i] = (char)tolower((unsigned char)iface[i]);
	}
	lower[len] = '\0';
	if (strncmp(lower, "wl", 2) == 0) {
		return 1;
	}
	if (strncmp(lower, "wlan", 4) == 0) {
		return 1;
	}
	return 0;
}
*/
import "C"

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"unsafe"
)

type LinuxNetkit struct{}

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
	cName := C.CString(ifaceName)
	defer C.free(unsafe.Pointer(cName))
	return C.LinuxIsWireless(cName) != 0
}

func (p *LinuxNetkit) getDefaultGatewayFromProc(ifaceName string) string {
	cName := C.CString(ifaceName)
	defer C.free(unsafe.Pointer(cName))
	ptr := C.CopyLinuxDefaultGateway(cName)
	if ptr == nil {
		return ""
	}
	defer C.free(unsafe.Pointer(ptr))
	return C.GoString(ptr)
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

func getLinuxDNSServers(path string) []string {
	cPath := C.CString(path)
	if cPath == nil {
		return nil
	}
	defer C.free(unsafe.Pointer(cPath))

	list := C.CopyLinuxDNSServers(cPath)
	defer C.FreeLinuxStringList(list)

	count := int(list.count)
	if count == 0 || list.items == nil {
		return nil
	}

	items := unsafe.Slice((**C.char)(list.items), count)
	result := make([]string, 0, count)
	for _, item := range items {
		if item != nil {
			result = append(result, C.GoString(item))
		}
	}

	runtime.KeepAlive(list)
	return result
}
