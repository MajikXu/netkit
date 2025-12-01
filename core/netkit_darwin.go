//go:build darwin
// +build darwin

package core

/*
#cgo CFLAGS: -x objective-c -fmodules -fobjc-arc
#cgo LDFLAGS: -framework CoreFoundation -framework SystemConfiguration -framework CoreWLAN -framework Foundation
#include <CoreFoundation/CoreFoundation.h>
#include <SystemConfiguration/SystemConfiguration.h>
#include <CoreWLAN/CoreWLAN.h>
#include <Foundation/Foundation.h>
#include <dispatch/dispatch.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
	char **items;
	size_t count;
} StringList;

typedef struct {
	char *deviceName;
	char *serviceID;
	char *configMethod;
	char *router;
} DarwinInterfaceConfig;

typedef struct {
	DarwinInterfaceConfig *items;
	size_t count;
} DarwinInterfaceConfigList;

typedef struct {
	char *primaryServiceID;
	char *primaryDevice;
	char *router;
} DarwinGlobalIPv4;

typedef struct {
	char *interfaceName;
	char *ssid;
	int rssi;
	int noise;
	double transmitRate;
	int channel;
	int channelWidth;
	int security;
} DarwinWiFiInfo;

typedef struct {
	DarwinWiFiInfo *items;
	size_t count;
} DarwinWiFiInfoList;

static char *dupCFString(CFStringRef value) {
	if (!value) {
		return NULL;
	}
	const char *inlineStr = CFStringGetCStringPtr(value, kCFStringEncodingUTF8);
	if (inlineStr) {
		return strdup(inlineStr);
	}
	CFIndex length = CFStringGetLength(value);
	CFIndex maxSize = CFStringGetMaximumSizeForEncoding(length, kCFStringEncodingUTF8) + 1;
	char *buffer = (char *)malloc((size_t)maxSize);
	if (!buffer) {
		return NULL;
	}
	if (!CFStringGetCString(value, buffer, maxSize, kCFStringEncodingUTF8)) {
		free(buffer);
		return NULL;
	}
	return buffer;
}

static void freeInterfaceConfig(DarwinInterfaceConfig config) {
	free(config.deviceName);
	free(config.serviceID);
	free(config.configMethod);
	free(config.router);
}

StringList CopyDNSServers(void) {
	StringList list = {0};
	SCDynamicStoreRef store = SCDynamicStoreCreate(NULL, CFSTR("netkit"), NULL, NULL);
	if (!store) {
		return list;
	}

	CFDictionaryRef dnsDict = SCDynamicStoreCopyValue(store, CFSTR("State:/Network/Global/DNS"));
	if (!dnsDict) {
		CFRelease(store);
		return list;
	}

	CFArrayRef servers = CFDictionaryGetValue(dnsDict, CFSTR("ServerAddresses"));
	if (!servers || CFGetTypeID(servers) != CFArrayGetTypeID()) {
		CFRelease(dnsDict);
		CFRelease(store);
		return list;
	}

	CFIndex count = CFArrayGetCount(servers);
	if (count <= 0) {
		CFRelease(dnsDict);
		CFRelease(store);
		return list;
	}

	list.items = (char **)calloc((size_t)count, sizeof(char *));
	if (!list.items) {
		CFRelease(dnsDict);
		CFRelease(store);
		return list;
	}

	list.count = (size_t)count;
	for (CFIndex i = 0; i < count; i++) {
		CFStringRef server = (CFStringRef)CFArrayGetValueAtIndex(servers, i);
		list.items[i] = dupCFString(server);
	}

	CFRelease(dnsDict);
	CFRelease(store);
	return list;
}

void FreeStringList(StringList list) {
	if (!list.items) {
		return;
	}
	for (size_t i = 0; i < list.count; i++) {
		free(list.items[i]);
	}
	free(list.items);
}

DarwinInterfaceConfigList CopyInterfaceConfigs(void) {
	DarwinInterfaceConfigList list = {0};
	SCDynamicStoreRef store = SCDynamicStoreCreate(NULL, CFSTR("netkit"), NULL, NULL);
	if (!store) {
		return list;
	}

	CFArrayRef ipv4Keys = SCDynamicStoreCopyKeyList(store, CFSTR("State:/Network/Service/[^/]+/IPv4"));
	if (!ipv4Keys) {
		CFRelease(store);
		return list;
	}

	CFIndex count = CFArrayGetCount(ipv4Keys);
	if (count <= 0) {
		CFRelease(ipv4Keys);
		CFRelease(store);
		return list;
	}

	list.items = (DarwinInterfaceConfig *)calloc((size_t)count, sizeof(DarwinInterfaceConfig));
	if (!list.items) {
		CFRelease(ipv4Keys);
		CFRelease(store);
		return list;
	}

	list.count = 0;
	for (CFIndex i = 0; i < count; i++) {
		CFStringRef key = (CFStringRef)CFArrayGetValueAtIndex(ipv4Keys, i);
		CFDictionaryRef ipv4Dict = SCDynamicStoreCopyValue(store, key);
		if (!ipv4Dict || CFGetTypeID(ipv4Dict) != CFDictionaryGetTypeID()) {
			if (ipv4Dict) {
				CFRelease(ipv4Dict);
			}
			continue;
		}

		DarwinInterfaceConfig config = (DarwinInterfaceConfig){0};

		CFStringRef configMethod = CFDictionaryGetValue(ipv4Dict, CFSTR("ConfigMethod"));
		if (configMethod) {
			config.configMethod = dupCFString(configMethod);
		}

		CFTypeRef routerValue = CFDictionaryGetValue(ipv4Dict, CFSTR("Router"));
		if (routerValue) {
			if (CFGetTypeID(routerValue) == CFStringGetTypeID()) {
				config.router = dupCFString((CFStringRef)routerValue);
			} else if (CFGetTypeID(routerValue) == CFArrayGetTypeID() && CFArrayGetCount((CFArrayRef)routerValue) > 0) {
				CFStringRef first = CFArrayGetValueAtIndex((CFArrayRef)routerValue, 0);
				config.router = dupCFString(first);
			}
		}

		char keyBuf[256];
		if (CFStringGetCString(key, keyBuf, sizeof(keyBuf), kCFStringEncodingUTF8)) {
			char *serviceStart = strstr(keyBuf, "Service/");
			if (serviceStart) {
				serviceStart += strlen("Service/");
				char *slash = strchr(serviceStart, '/');
				if (slash) {
					size_t len = (size_t)(slash - serviceStart);
					if (len < sizeof(keyBuf)) {
						char serviceID[256];
						memcpy(serviceID, serviceStart, len);
						serviceID[len] = '\0';
						config.serviceID = strdup(serviceID);
					}
				}
			}
		}

		if (config.serviceID) {
			CFStringRef serviceCF = CFStringCreateWithCString(NULL, config.serviceID, kCFStringEncodingUTF8);
			if (serviceCF) {
				CFStringRef interfaceKey = SCDynamicStoreKeyCreateNetworkServiceEntity(NULL, kSCDynamicStoreDomainState, serviceCF, kSCEntNetInterface);
				if (interfaceKey) {
					CFDictionaryRef interfaceDict = SCDynamicStoreCopyValue(store, interfaceKey);
					if (interfaceDict && CFGetTypeID(interfaceDict) == CFDictionaryGetTypeID()) {
						CFStringRef device = CFDictionaryGetValue(interfaceDict, CFSTR("DeviceName"));
						if (device) {
							config.deviceName = dupCFString(device);
						}
					}
					if (interfaceDict) {
						CFRelease(interfaceDict);
					}
					CFRelease(interfaceKey);
				}
				CFRelease(serviceCF);
			}
		}

		if (config.deviceName) {
			list.items[list.count++] = config;
		} else {
			freeInterfaceConfig(config);
		}

		CFRelease(ipv4Dict);
	}

	CFRelease(ipv4Keys);
	CFRelease(store);
	return list;
}

void FreeInterfaceConfigList(DarwinInterfaceConfigList list) {
	if (!list.items) {
		return;
	}
	for (size_t i = 0; i < list.count; i++) {
		freeInterfaceConfig(list.items[i]);
	}
	free(list.items);
}

DarwinGlobalIPv4 CopyGlobalIPv4(void) {
	DarwinGlobalIPv4 info = {0};
	SCDynamicStoreRef store = SCDynamicStoreCreate(NULL, CFSTR("netkit"), NULL, NULL);
	if (!store) {
		return info;
	}

	CFDictionaryRef dict = SCDynamicStoreCopyValue(store, CFSTR("State:/Network/Global/IPv4"));
	if (!dict) {
		CFRelease(store);
		return info;
	}

	CFStringRef primaryService = CFDictionaryGetValue(dict, CFSTR("PrimaryService"));
	if (primaryService) {
		info.primaryServiceID = dupCFString(primaryService);
	}

	CFStringRef primaryInterface = CFDictionaryGetValue(dict, CFSTR("PrimaryInterface"));
	if (primaryInterface) {
		info.primaryDevice = dupCFString(primaryInterface);
	}

	CFTypeRef routerValue = CFDictionaryGetValue(dict, CFSTR("Router"));
	if (routerValue) {
		if (CFGetTypeID(routerValue) == CFStringGetTypeID()) {
			info.router = dupCFString((CFStringRef)routerValue);
		} else if (CFGetTypeID(routerValue) == CFArrayGetTypeID() && CFArrayGetCount((CFArrayRef)routerValue) > 0) {
			CFStringRef first = CFArrayGetValueAtIndex((CFArrayRef)routerValue, 0);
			info.router = dupCFString(first);
		}
	}

	CFRelease(dict);
	CFRelease(store);
	return info;
}

void FreeGlobalIPv4(DarwinGlobalIPv4 info) {
	free(info.primaryServiceID);
	free(info.primaryDevice);
	free(info.router);
}

DarwinWiFiInfoList CopyWiFiInfo(void) {
	__block DarwinWiFiInfoList list = {0};
	dispatch_block_t work = ^{
		@autoreleasepool {
			CWWiFiClient *client = [CWWiFiClient sharedWiFiClient];
			NSArray<CWInterface *> *interfaces = [client interfaces];
			if (!interfaces || interfaces.count == 0) {
				return;
			}
			SCDynamicStoreRef store = SCDynamicStoreCreate(NULL, CFSTR("netkit"), NULL, NULL);
			list.count = interfaces.count;
			list.items = (DarwinWiFiInfo *)calloc((size_t)list.count, sizeof(DarwinWiFiInfo));
			if (!list.items) {
				if (store) {
					CFRelease(store);
				}
				list.count = 0;
				return;
			}
			for (NSUInteger idx = 0; idx < interfaces.count; idx++) {
				CWInterface *iface = interfaces[idx];
				DarwinWiFiInfo info = (DarwinWiFiInfo){0};
				if (iface.interfaceName) {
					info.interfaceName = strdup(iface.interfaceName.UTF8String);
				}
				NSString *ssidString = iface.ssid;
				NSData *ssidData = iface.ssidData;
				if ((!ssidString || ssidString.length == 0) && store && iface.interfaceName) {
					CFStringRef key = CFStringCreateWithFormat(NULL, NULL, CFSTR("State:/Network/Interface/%@/AirPort"), (__bridge CFStringRef)iface.interfaceName);
					if (key) {
						CFDictionaryRef airportDict = SCDynamicStoreCopyValue(store, key);
						if (airportDict && CFGetTypeID(airportDict) == CFDictionaryGetTypeID()) {
							CFStringRef ssidStrValue = CFDictionaryGetValue(airportDict, CFSTR("SSID_STR"));
							if (ssidStrValue) {
								ssidString = [[NSString alloc] initWithString:(__bridge NSString *)ssidStrValue];
							}
							if ((!ssidString || ssidString.length == 0)) {
								CFDataRef ssidRaw = CFDictionaryGetValue(airportDict, CFSTR("SSID"));
								if (ssidRaw && CFGetTypeID(ssidRaw) == CFDataGetTypeID()) {
									ssidData = [NSData dataWithData:(__bridge NSData *)ssidRaw];
								}
							}
						}
						if (airportDict) {
							CFRelease(airportDict);
						}
						CFRelease(key);
					}
				}
				if (ssidString && ssidString.length > 0) {
					info.ssid = strdup(ssidString.UTF8String);
				} else if (ssidData.length > 0) {
					size_t length = (size_t)ssidData.length;
					const char *bytes = (const char *)ssidData.bytes;
					char *buffer = (char *)malloc(length + 1);
					if (buffer) {
						memcpy(buffer, bytes, length);
						buffer[length] = '\0';
						info.ssid = buffer;
					}
				}
				info.rssi = (int)iface.rssiValue;
				info.noise = (int)iface.noiseMeasurement;
				info.transmitRate = iface.transmitRate;
				CWChannel *channel = iface.wlanChannel;
				if (channel) {
					info.channel = (int)channel.channelNumber;
					switch (channel.channelWidth) {
					case kCWChannelWidth20MHz:
						info.channelWidth = 20;
						break;
					case kCWChannelWidth40MHz:
						info.channelWidth = 40;
						break;
					case kCWChannelWidth80MHz:
						info.channelWidth = 80;
						break;
					case kCWChannelWidth160MHz:
						info.channelWidth = 160;
						break;
					default:
						info.channelWidth = 0;
						break;
					}
				}
				info.security = (int)iface.security;
				list.items[idx] = info;
			}
			if (store) {
				CFRelease(store);
			}
		}
	};
	if ([NSThread isMainThread]) {
		work();
	} else {
		dispatch_sync(dispatch_get_main_queue(), work);
	}
	return list;
}

void FreeWiFiInfoList(DarwinWiFiInfoList list) {
	if (!list.items) {
		return;
	}
	for (size_t i = 0; i < list.count; i++) {
		free(list.items[i].interfaceName);
		free(list.items[i].ssid);
	}
	free(list.items);
}
*/
import "C"

import (
	"bufio"
	"fmt"
	"math"
	"net"
	"os"
	"runtime"
	"strings"
	"unsafe"
)

type DarwinNetkit struct{}

func DefaultNetkit() Netkit { return NewDarwinNetkit() }

func NewDarwinNetkit() *DarwinNetkit { return &DarwinNetkit{} }

func (p *DarwinNetkit) Hostname() (string, error) { return os.Hostname() }

func (p *DarwinNetkit) DNSServers() ([]string, error) {
	if servers := getDarwinDNSServers(); len(servers) > 0 {
		return servers, nil
	}
	return readResolvConfNameservers("/etc/resolv.conf"), nil
}

func (p *DarwinNetkit) LanInterfaces() ([]LanNetworkInterface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	configs := getDarwinInterfaceConfigMap()
	global := getDarwinGlobalIPv4()
	wifiInfos := getDarwinWiFiInfoMap()

	var lan []LanNetworkInterface
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if isWirelessInterfaceName(iface.Name, wifiInfos) {
			continue
		}

		ni, err := p.buildNetworkInterface(iface, configs, global)
		if err != nil {
			continue
		}

		lan = append(lan, LanNetworkInterface{Interface: ni})
	}

	return lan, nil
}

func (p *DarwinNetkit) WlanInterfaces() ([]WlanNetworkInterface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	configs := getDarwinInterfaceConfigMap()
	global := getDarwinGlobalIPv4()
	wifiInfos := getDarwinWiFiInfoMap()

	var wlan []WlanNetworkInterface
	for _, iface := range ifaces {
		info, infoOK := wifiInfos[iface.Name]
		if !infoOK && !isWirelessInterfaceName(iface.Name, wifiInfos) {
			continue
		}

		ni, err := p.buildNetworkInterface(iface, configs, global)
		if err != nil {
			continue
		}

		w := WlanNetworkInterface{
			Interface: ni,
			Security:  WlanSecurityUnknown,
		}

		if infoOK {
			if info.SSID != "" {
				w.SSID = info.SSID
			}
			if info.Channel > 0 {
				w.Channel = int32(info.Channel)
				if freq := frequencyForChannel(info.Channel); freq != 0 {
					w.Frequency = freq
				}
			}
			if info.ChannelWidth > 0 {
				w.ChannelWidth = int32(info.ChannelWidth)
			}
			if info.TransmitRate > 0 {
				w.LinkSpeedTx = int32(math.Round(info.TransmitRate))
			}
			if info.RSSI != 0 {
				rssi := int32(info.RSSI)
				w.SignalStrengthUnfiltered = rssi
				w.SignalStrength = rssiToSignalStrength(rssi)
			}
			w.Security = convertCWSecurity(info.Security)
		}

		wlan = append(wlan, w)
	}

	return wlan, nil
}

func (p *DarwinNetkit) buildNetworkInterface(iface net.Interface, configs map[string]darwinInterfaceConfig, global darwinGlobalIPv4) (NetworkInterface, error) {
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

	cfg, cfgOK := configs[iface.Name]
	gateway := ""
	if cfgOK && cfg.Router != "" {
		gateway = cfg.Router
	}

	if gateway == "" && global.Router != "" {
		if cfgOK && cfg.ServiceID != "" && cfg.ServiceID == global.PrimaryServiceID {
			gateway = global.Router
		} else if global.PrimaryDevice != "" && iface.Name == global.PrimaryDevice {
			gateway = global.Router
		}
	}

	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}

		ip := ipNet.IP
		var addrType NetworkAddressType
		var mask string

		if ip.To4() != nil {
			addrType = NetworkAddressTypeV4
			mask = ipv4MaskString(ipNet.Mask)
		} else if ip.To16() != nil {
			addrType = NetworkAddressTypeV6
			ones, _ := ipNet.Mask.Size()
			mask = fmt.Sprintf("%d", ones)
		} else {
			continue
		}

		ni.Addresses = append(ni.Addresses, NetworkAddress{
			Type:       addrType,
			Address:    ip.String(),
			SubnetMask: mask,
			Gateway:    gateway,
		})
	}

	if cfgOK && isDHCPMethod(cfg.ConfigMethod) {
		ni.Mode = IpModeDHCP
	} else if len(ni.Addresses) > 0 {
		ni.Mode = IpModeStatic
	}

	return ni, nil
}

func isWirelessInterfaceName(name string, wifi map[string]darwinWiFiInfo) bool {
	if _, ok := wifi[name]; ok {
		return true
	}
	lname := strings.ToLower(name)
	if strings.HasPrefix(lname, "en") && (lname == "en0" || lname == "en1") {
		return true
	}
	return strings.HasPrefix(lname, "wl")
}

func isDHCPMethod(method string) bool {
	m := strings.ToLower(strings.TrimSpace(method))
	switch m {
	case "dhcp", "bootp", "automatic", "linklocal":
		return true
	default:
		return false
	}
}

func convertCWSecurity(sec int) WlanSecurity {
	switch sec {
	case 0:
		return WlanSecurityOpen
	case 1:
		return WlanSecurityWEP
	case 2, 3, 5, 6:
		return WlanSecurityWPA
	case 4, 11:
		return WlanSecurityWPA2
	case 7, 8, 9, 10:
		return WlanSecurityWPA2EAP
	case 12:
		return WlanSecurityWPA3SAE
	case 13, 14, 15:
		return WlanSecurityWPA3EAP
	default:
		return WlanSecurityUnknown
	}
}

func frequencyForChannel(channel int) int32 {
	switch {
	case channel >= 1 && channel <= 14:
		return int32(2407 + channel*5)
	case channel >= 36 && channel <= 177:
		return int32(5000 + channel*5)
	case channel >= 1 && channel <= 233:
		return int32(5940 + channel*5)
	default:
		return 0
	}
}

func rssiToSignalStrength(rssi int32) SignalStrength {
	if rssi >= -50 {
		return SignalStrengthExcellent
	}
	if rssi >= -60 {
		return SignalStrengthGood
	}
	if rssi >= -70 {
		return SignalStrengthFair
	}
	if rssi >= -80 {
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
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
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

type darwinInterfaceConfig struct {
	DeviceName   string
	ServiceID    string
	ConfigMethod string
	Router       string
}

type darwinGlobalIPv4 struct {
	PrimaryServiceID string
	PrimaryDevice    string
	Router           string
}

type darwinWiFiInfo struct {
	InterfaceName string
	SSID          string
	RSSI          int
	Noise         int
	TransmitRate  float64
	Channel       int
	ChannelWidth  int
	Security      int
}

func getDarwinDNSServers() []string {
	list := C.CopyDNSServers()
	defer C.FreeStringList(list)

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

func getDarwinInterfaceConfigMap() map[string]darwinInterfaceConfig {
	list := C.CopyInterfaceConfigs()
	defer C.FreeInterfaceConfigList(list)

	count := int(list.count)
	configs := make(map[string]darwinInterfaceConfig, count)
	if count == 0 || list.items == nil {
		return configs
	}

	items := unsafe.Slice((*C.DarwinInterfaceConfig)(list.items), count)
	for _, item := range items {
		if item.deviceName == nil {
			continue
		}
		name := C.GoString(item.deviceName)
		cfg := darwinInterfaceConfig{DeviceName: name}
		if item.serviceID != nil {
			cfg.ServiceID = C.GoString(item.serviceID)
		}
		if item.configMethod != nil {
			cfg.ConfigMethod = C.GoString(item.configMethod)
		}
		if item.router != nil {
			cfg.Router = C.GoString(item.router)
		}
		configs[name] = cfg
	}

	runtime.KeepAlive(list)
	return configs
}

func getDarwinGlobalIPv4() darwinGlobalIPv4 {
	info := C.CopyGlobalIPv4()
	defer C.FreeGlobalIPv4(info)

	result := darwinGlobalIPv4{}
	if info.primaryServiceID != nil {
		result.PrimaryServiceID = C.GoString(info.primaryServiceID)
	}
	if info.primaryDevice != nil {
		result.PrimaryDevice = C.GoString(info.primaryDevice)
	}
	if info.router != nil {
		result.Router = C.GoString(info.router)
	}

	runtime.KeepAlive(info)
	return result
}

func getDarwinWiFiInfoMap() map[string]darwinWiFiInfo {
	list := C.CopyWiFiInfo()
	defer C.FreeWiFiInfoList(list)

	count := int(list.count)
	infos := make(map[string]darwinWiFiInfo, count)
	if count == 0 || list.items == nil {
		return infos
	}

	items := unsafe.Slice((*C.DarwinWiFiInfo)(list.items), count)
	for _, item := range items {
		if item.interfaceName == nil {
			continue
		}
		name := C.GoString(item.interfaceName)
		info := darwinWiFiInfo{
			InterfaceName: name,
			RSSI:          int(item.rssi),
			Noise:         int(item.noise),
			TransmitRate:  float64(item.transmitRate),
			Channel:       int(item.channel),
			ChannelWidth:  int(item.channelWidth),
			Security:      int(item.security),
		}
		if item.ssid != nil {
			info.SSID = C.GoString(item.ssid)
		}
		infos[name] = info
	}

	runtime.KeepAlive(list)
	return infos
}
