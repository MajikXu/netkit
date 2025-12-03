//go:build darwin
// +build darwin

package core

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"unsafe"

	"github.com/ebitengine/purego"
)

type DarwinNetkit struct{}

func DefaultNetkit() Netkit { return NewDarwinNetkit() }

func NewDarwinNetkit() *DarwinNetkit {
	_ = ensureSystemConfiguration()
	return &DarwinNetkit{}
}

func (d *DarwinNetkit) Hostname() (string, error) { return os.Hostname() }

func (d *DarwinNetkit) DNSServers() ([]string, error) {
	servers, err := fetchDarwinDNSServers()
	if len(servers) > 0 {
		return servers, nil
	}
	fallback := readResolvConfNameservers("/etc/resolv.conf")
	if len(fallback) > 0 {
		return fallback, nil
	}
	if err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("no DNS servers found")
}

func (d *DarwinNetkit) LanInterfaces() ([]LanNetworkInterface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	typeMap, _ := gatherInterfaceTypes()
	configs := gatherDarwinInterfaceConfigs()
	var lan []LanNetworkInterface
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if category, ok := typeMap[iface.Name]; ok && category == interfaceCategoryWiFi {
			continue
		}
		cfg := darwinInterfaceConfig{}
		if configs != nil {
			cfg = configs[iface.Name]
		}
		ni, buildErr := buildDarwinInterface(iface, cfg.mode, cfg.gateway)
		if buildErr != nil {
			continue
		}
		lan = append(lan, LanNetworkInterface{Interface: ni})
	}
	return lan, nil
}

func (d *DarwinNetkit) WlanInterfaces() ([]WlanNetworkInterface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	typeMap, _ := gatherInterfaceTypes()
	configs := gatherDarwinInterfaceConfigs()
	overrides := gatherCaptiveNetworkDetails()
	var wlan []WlanNetworkInterface
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if category, ok := typeMap[iface.Name]; !ok || category != interfaceCategoryWiFi {
			continue
		}
		cfg := darwinInterfaceConfig{}
		if configs != nil {
			cfg = configs[iface.Name]
		}
		ni, buildErr := buildDarwinInterface(iface, cfg.mode, cfg.gateway)
		if buildErr != nil {
			continue
		}
		details := fetchDarwinWiFiDetails(iface.Name, overrides)
		w := WlanNetworkInterface{
			Interface:                ni,
			Security:                 WlanSecurityUnknown,
			SignalStrength:           SignalStrengthUnknown,
			Channel:                  0,
			Frequency:                0,
			ChannelWidth:             0,
			LinkSpeedTx:              0,
			SignalStrengthUnfiltered: 0,
		}
		if details != nil {
			if details.SSID != "" {
				w.SSID = details.SSID
			}
			if details.Security != "" {
				w.Security = parseDarwinWiFiSecurity(details.Security)
			}
			if details.Channel != 0 {
				w.Channel = int32(details.Channel)
			}
			if details.ChannelWidth != 0 {
				w.ChannelWidth = int32(details.ChannelWidth)
			}
			if details.Frequency != 0 {
				w.Frequency = int32(details.Frequency)
			} else if freq := channelToFrequency(details.Channel); freq != 0 {
				w.Frequency = int32(freq)
			}
			if details.LinkRate != 0 {
				w.LinkSpeedTx = int32(details.LinkRate)
			}
			if details.RSSI != 0 {
				rssi := int32(details.RSSI)
				w.SignalStrengthUnfiltered = rssi
				w.SignalStrength = signalStrengthFromRSSI(rssi)
			}
		}
		wlan = append(wlan, w)
	}
	return wlan, nil
}

type (
	CFTypeRef             unsafe.Pointer
	CFStringRef           unsafe.Pointer
	CFArrayRef            unsafe.Pointer
	CFDictionaryRef       unsafe.Pointer
	CFAllocatorRef        unsafe.Pointer
	CFIndex               int64
	CFTypeID              uintptr
	CFDataRef             unsafe.Pointer
	SCDynamicStoreRef     unsafe.Pointer
	SCNetworkInterfaceRef unsafe.Pointer
	CFNumberRef           unsafe.Pointer
	CFBooleanRef          unsafe.Pointer
	CFNumberType          uint32
	CFStringEncoding      uint32
	Boolean               uint8
	objcID                unsafe.Pointer
	SEL                   uintptr
)

const (
	kCFStringEncodingUTF8 CFStringEncoding = 0x08000100
	kCFNumberSInt64Type   CFNumberType     = 4
	kCFNumberSInt32Type   CFNumberType     = 3
)

var (
	loadOnce sync.Once
	loadErr  error

	cfHandle       uintptr
	scHandle       uintptr
	objcHandle     uintptr
	coreWLANHandle uintptr
	dispatchHandle uintptr

	cfRelease                         func(CFTypeRef)
	cfStringCreateWithCString         func(CFAllocatorRef, *byte, CFStringEncoding) CFStringRef
	cfStringGetCString                func(CFStringRef, *byte, CFIndex, CFStringEncoding) Boolean
	cfStringGetCStringPtr             func(CFStringRef, CFStringEncoding) *byte
	cfStringGetLength                 func(CFStringRef) CFIndex
	cfStringGetMaximumSizeForEncoding func(CFIndex, CFStringEncoding) CFIndex
	cfArrayGetCount                   func(CFArrayRef) CFIndex
	cfArrayGetValueAtIndex            func(CFArrayRef, CFIndex) unsafe.Pointer
	cfDictionaryGetValueIfPresent     func(CFDictionaryRef, unsafe.Pointer, *unsafe.Pointer) Boolean
	cfDictionaryGetTypeID             func() CFTypeID
	cfArrayGetTypeID                  func() CFTypeID
	cfStringGetTypeID                 func() CFTypeID
	cfGetTypeID                       func(CFTypeRef) CFTypeID
	cfEqual                           func(CFTypeRef, CFTypeRef) Boolean
	cfNumberGetValue                  func(CFNumberRef, CFNumberType, unsafe.Pointer) Boolean
	cfNumberGetTypeID                 func() CFTypeID
	cfDataGetLength                   func(CFDataRef) CFIndex
	cfDataGetBytePtr                  func(CFDataRef) *byte
	cfDataGetTypeID                   func() CFTypeID

	scDynamicStoreCreate               func(CFAllocatorRef, CFStringRef, uintptr, uintptr) SCDynamicStoreRef
	scDynamicStoreCopyValue            func(SCDynamicStoreRef, CFStringRef) CFTypeRef
	scDynamicStoreCopyKeyList          func(SCDynamicStoreRef, CFStringRef) CFArrayRef
	scNetworkInterfaceCopyAll          func() CFArrayRef
	scNetworkInterfaceGetBSDName       func(SCNetworkInterfaceRef) CFStringRef
	scNetworkInterfaceGetInterfaceType func(SCNetworkInterfaceRef) CFStringRef
	objc_getClass                      func(*byte) objcID
	sel_registerName                   func(*byte) SEL
	objc_msgSend                       func(objcID, SEL) objcID
	objc_msgSend_objcID                func(objcID, SEL, objcID) objcID
	objc_msgSend_ptr                   func(objcID, SEL, unsafe.Pointer) objcID
	objc_msgSend_char                  func(objcID, SEL) unsafe.Pointer
	objc_msgSend_int                   func(objcID, SEL) int64
	objc_msgSend_uintptr               func(objcID, SEL, uintptr) objcID
	cnCopySupportedInterfaces          func() CFArrayRef
	cnCopyCurrentNetworkInfo           func(CFStringRef) CFDictionaryRef
	dispatch_get_main_queue            func() unsafe.Pointer
	dispatch_sync_f                    func(unsafe.Pointer, unsafe.Pointer, uintptr)

	cfDictionaryTypeID   CFTypeID
	cfArrayTypeID        CFTypeID
	cfStringTypeID       CFTypeID
	cfNumberTypeID       CFTypeID
	cfDataTypeID         CFTypeID
	coreWLANReady        bool
	captiveNetworkReady  bool
	dispatchCallback     uintptr
	dispatchCallbackOnce sync.Once
	dispatchCallbackMu   sync.Mutex
	dispatchCallbackFn   func()
)

func ensureSystemConfiguration() error {
	loadOnce.Do(func() {
		loadErr = loadSystemConfiguration()
	})
	return loadErr
}

func loadSystemConfiguration() error {
	var err error
	cfHandle, err = purego.Dlopen("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", purego.RTLD_NOW|purego.RTLD_GLOBAL)
	if err != nil {
		return fmt.Errorf("load CoreFoundation: %w", err)
	}
	scHandle, err = purego.Dlopen("/System/Library/Frameworks/SystemConfiguration.framework/SystemConfiguration", purego.RTLD_NOW|purego.RTLD_GLOBAL)
	if err != nil {
		return fmt.Errorf("load SystemConfiguration: %w", err)
	}
	purego.RegisterLibFunc(&cfRelease, cfHandle, "CFRelease")
	purego.RegisterLibFunc(&cfStringCreateWithCString, cfHandle, "CFStringCreateWithCString")
	purego.RegisterLibFunc(&cfStringGetCString, cfHandle, "CFStringGetCString")
	purego.RegisterLibFunc(&cfStringGetCStringPtr, cfHandle, "CFStringGetCStringPtr")
	purego.RegisterLibFunc(&cfStringGetLength, cfHandle, "CFStringGetLength")
	purego.RegisterLibFunc(&cfStringGetMaximumSizeForEncoding, cfHandle, "CFStringGetMaximumSizeForEncoding")
	purego.RegisterLibFunc(&cfArrayGetCount, cfHandle, "CFArrayGetCount")
	purego.RegisterLibFunc(&cfArrayGetValueAtIndex, cfHandle, "CFArrayGetValueAtIndex")
	purego.RegisterLibFunc(&cfDictionaryGetValueIfPresent, cfHandle, "CFDictionaryGetValueIfPresent")
	purego.RegisterLibFunc(&cfDictionaryGetTypeID, cfHandle, "CFDictionaryGetTypeID")
	purego.RegisterLibFunc(&cfArrayGetTypeID, cfHandle, "CFArrayGetTypeID")
	purego.RegisterLibFunc(&cfStringGetTypeID, cfHandle, "CFStringGetTypeID")
	purego.RegisterLibFunc(&cfGetTypeID, cfHandle, "CFGetTypeID")
	purego.RegisterLibFunc(&cfEqual, cfHandle, "CFEqual")
	purego.RegisterLibFunc(&cfNumberGetValue, cfHandle, "CFNumberGetValue")
	purego.RegisterLibFunc(&cfNumberGetTypeID, cfHandle, "CFNumberGetTypeID")
	purego.RegisterLibFunc(&cfDataGetLength, cfHandle, "CFDataGetLength")
	purego.RegisterLibFunc(&cfDataGetBytePtr, cfHandle, "CFDataGetBytePtr")
	purego.RegisterLibFunc(&cfDataGetTypeID, cfHandle, "CFDataGetTypeID")
	purego.RegisterLibFunc(&scDynamicStoreCreate, scHandle, "SCDynamicStoreCreate")
	purego.RegisterLibFunc(&scDynamicStoreCopyValue, scHandle, "SCDynamicStoreCopyValue")
	purego.RegisterLibFunc(&scDynamicStoreCopyKeyList, scHandle, "SCDynamicStoreCopyKeyList")
	purego.RegisterLibFunc(&scNetworkInterfaceCopyAll, scHandle, "SCNetworkInterfaceCopyAll")
	purego.RegisterLibFunc(&scNetworkInterfaceGetBSDName, scHandle, "SCNetworkInterfaceGetBSDName")
	purego.RegisterLibFunc(&scNetworkInterfaceGetInterfaceType, scHandle, "SCNetworkInterfaceGetInterfaceType")
	objcHandle, err = purego.Dlopen("/usr/lib/libobjc.A.dylib", purego.RTLD_NOW|purego.RTLD_GLOBAL)
	if err == nil {
		purego.RegisterLibFunc(&objc_getClass, objcHandle, "objc_getClass")
		purego.RegisterLibFunc(&sel_registerName, objcHandle, "sel_registerName")
		purego.RegisterLibFunc(&objc_msgSend, objcHandle, "objc_msgSend")
		purego.RegisterLibFunc(&objc_msgSend_objcID, objcHandle, "objc_msgSend")
		purego.RegisterLibFunc(&objc_msgSend_ptr, objcHandle, "objc_msgSend")
		purego.RegisterLibFunc(&objc_msgSend_char, objcHandle, "objc_msgSend")
		purego.RegisterLibFunc(&objc_msgSend_int, objcHandle, "objc_msgSend")
		purego.RegisterLibFunc(&objc_msgSend_uintptr, objcHandle, "objc_msgSend")
	} else {
		objcHandle = 0
	}
	coreWLANHandle, err = purego.Dlopen("/System/Library/Frameworks/CoreWLAN.framework/CoreWLAN", purego.RTLD_NOW|purego.RTLD_GLOBAL)
	if err == nil {
		coreWLANReady = objcHandle != 0 && coreWLANHandle != 0
	} else {
		coreWLANHandle = 0
		coreWLANReady = false
	}
	if coreWLANReady {
		if objc_getClass == nil || sel_registerName == nil || objc_msgSend == nil || objc_msgSend_char == nil {
			coreWLANReady = false
		}
	}
	dispatchHandle, err = purego.Dlopen("/usr/lib/libSystem.B.dylib", purego.RTLD_NOW|purego.RTLD_GLOBAL)
	if err == nil {
		if sym, symErr := purego.Dlsym(dispatchHandle, "dispatch_get_main_queue"); symErr == nil && sym != 0 {
			purego.RegisterFunc(&dispatch_get_main_queue, sym)
		}
		if sym, symErr := purego.Dlsym(dispatchHandle, "dispatch_sync_f"); symErr == nil && sym != 0 {
			purego.RegisterFunc(&dispatch_sync_f, sym)
		}
	} else {
		dispatchHandle = 0
	}
	purego.RegisterLibFunc(&cnCopySupportedInterfaces, scHandle, "CNCopySupportedInterfaces")
	purego.RegisterLibFunc(&cnCopyCurrentNetworkInfo, scHandle, "CNCopyCurrentNetworkInfo")
	captiveNetworkReady = cnCopySupportedInterfaces != nil && cnCopyCurrentNetworkInfo != nil
	cfDictionaryTypeID = cfDictionaryGetTypeID()
	cfArrayTypeID = cfArrayGetTypeID()
	cfStringTypeID = cfStringGetTypeID()
	if cfNumberGetTypeID != nil {
		cfNumberTypeID = cfNumberGetTypeID()
	}
	if cfDataGetTypeID != nil {
		cfDataTypeID = cfDataGetTypeID()
	}
	return nil
}

func runOnMainQueue(fn func()) bool {
	if fn == nil || dispatch_sync_f == nil || dispatch_get_main_queue == nil {
		return false
	}
	ensureDispatchCallback()
	queue := dispatch_get_main_queue()
	if queue == nil {
		return false
	}
	dispatchCallbackMu.Lock()
	dispatchCallbackFn = fn
	dispatchCallbackMu.Unlock()
	defer func() {
		dispatchCallbackMu.Lock()
		dispatchCallbackFn = nil
		dispatchCallbackMu.Unlock()
	}()
	dispatch_sync_f(queue, nil, dispatchCallback)
	return true
}

func ensureDispatchCallback() {
	dispatchCallbackOnce.Do(func() {
		dispatchCallback = purego.NewCallback(func(_ unsafe.Pointer) {
			dispatchCallbackMu.Lock()
			fn := dispatchCallbackFn
			dispatchCallbackMu.Unlock()
			if fn != nil {
				fn()
			}
		})
	})
}

func fetchDarwinDNSServers() ([]string, error) {
	if err := ensureSystemConfiguration(); err != nil {
		return nil, err
	}
	store, err := newDynamicStore("netkit.dns")
	if err != nil {
		return nil, err
	}
	defer releaseCF(CFTypeRef(store))
	key, err := makeCFString("State:/Network/Global/DNS")
	if err != nil {
		return nil, err
	}
	defer releaseCF(CFTypeRef(key))
	value := scDynamicStoreCopyValue(store, key)
	if value == nil {
		return nil, fmt.Errorf("dynamic store returned nil")
	}
	defer releaseCF(value)
	if cfGetTypeID(value) != cfDictionaryTypeID {
		return nil, fmt.Errorf("unexpected DNS value type")
	}
	servers, err := cfDictionaryCopyStringArray(CFDictionaryRef(value), "ServerAddresses")
	if err != nil {
		return nil, err
	}
	if len(servers) == 0 {
		return nil, fmt.Errorf("DNS server list empty")
	}
	return servers, nil
}

type interfaceCategory int

const (
	interfaceCategoryUnknown interfaceCategory = iota
	interfaceCategoryEthernet
	interfaceCategoryWiFi
)

type darwinWiFiDetails struct {
	SSID         string
	Security     string
	RSSI         int
	Channel      int
	Frequency    int
	ChannelWidth int
	LinkRate     int
	RadioType    string
}

func (d *darwinWiFiDetails) merge(other *darwinWiFiDetails) {
	if d == nil || other == nil {
		return
	}
	if d.SSID == "" {
		d.SSID = other.SSID
	}
	if d.Security == "" {
		d.Security = other.Security
	}
	if d.RSSI == 0 {
		d.RSSI = other.RSSI
	}
	if d.Channel == 0 {
		d.Channel = other.Channel
	}
	if d.Frequency == 0 {
		d.Frequency = other.Frequency
	}
	if d.ChannelWidth == 0 {
		d.ChannelWidth = other.ChannelWidth
	}
	if d.LinkRate == 0 {
		d.LinkRate = other.LinkRate
	}
	if d.RadioType == "" {
		d.RadioType = other.RadioType
	}
}

func (d *darwinWiFiDetails) isEmpty() bool {
	if d == nil {
		return true
	}
	return d.SSID == "" && d.Security == "" && d.RSSI == 0 && d.Channel == 0 && d.Frequency == 0 && d.ChannelWidth == 0 && d.LinkRate == 0 && d.RadioType == ""
}

type darwinInterfaceConfig struct {
	mode    IpMode
	gateway string
}

func gatherDarwinInterfaceConfigs() map[string]darwinInterfaceConfig {
	if err := ensureSystemConfiguration(); err != nil {
		return nil
	}
	store, err := newDynamicStore("netkit.interface.configs")
	if err != nil {
		return nil
	}
	defer releaseCF(CFTypeRef(store))
	pattern, err := makeCFString("State:/Network/Service/.*/IPv4")
	if err != nil {
		return nil
	}
	defer releaseCF(CFTypeRef(pattern))
	keys := scDynamicStoreCopyKeyList(store, pattern)
	if keys == nil {
		return nil
	}
	defer releaseCF(CFTypeRef(keys))
	result := make(map[string]darwinInterfaceConfig)
	count := int(cfArrayGetCount(keys))
	for i := 0; i < count; i++ {
		keyPtr := cfArrayGetValueAtIndex(keys, CFIndex(i))
		if keyPtr == nil {
			continue
		}
		key := cfStringToGoString(CFStringRef(keyPtr))
		if key == "" {
			continue
		}
		keyRef, err := makeCFString(key)
		if err != nil {
			continue
		}
		value := scDynamicStoreCopyValue(store, keyRef)
		releaseCF(CFTypeRef(keyRef))
		if value == nil {
			continue
		}
		stateDict := CFDictionaryRef(value)
		ifaceName := ""
		if name, ok := cfDictionaryCopyStringValue(stateDict, "ConfirmedInterfaceName"); ok && name != "" {
			ifaceName = name
		}
		if ifaceName == "" {
			if name, ok := cfDictionaryCopyStringValue(stateDict, "InterfaceName"); ok && name != "" {
				ifaceName = name
			}
		}
		cfg := result[ifaceName]
		if ifaceName != "" {
			if router, ok := cfDictionaryCopyStringValue(stateDict, "Router"); ok && router != "" {
				cfg.gateway = router
			}
		}
		releaseCF(value)
		if ifaceName == "" {
			continue
		}
		setupKey := strings.Replace(key, "State:/", "Setup:/", 1)
		setupRef, err := makeCFString(setupKey)
		if err == nil {
			if setupValue := scDynamicStoreCopyValue(store, setupRef); setupValue != nil {
				setupDict := CFDictionaryRef(setupValue)
				if method, ok := cfDictionaryCopyStringValue(setupDict, "ConfigMethod"); ok {
					cfg.mode = parseDarwinConfigMethod(method)
				}
				releaseCF(setupValue)
			}
			releaseCF(CFTypeRef(setupRef))
		}
		if cfg.mode == IpModeNone {
			dhcpKey := strings.Replace(key, "/IPv4", "/DHCP", 1)
			dhcpRef, err := makeCFString(dhcpKey)
			if err == nil {
				if dhcpValue := scDynamicStoreCopyValue(store, dhcpRef); dhcpValue != nil {
					cfg.mode = IpModeDHCP
					releaseCF(dhcpValue)
				}
				releaseCF(CFTypeRef(dhcpRef))
			}
		}
		if cfg.mode == IpModeNone && cfg.gateway != "" {
			cfg.mode = IpModeStatic
		}
		result[ifaceName] = cfg
	}
	globalRef, err := makeCFString("State:/Network/Global/IPv4")
	if err == nil {
		if globalValue := scDynamicStoreCopyValue(store, globalRef); globalValue != nil {
			globalDict := CFDictionaryRef(globalValue)
			if router, ok := cfDictionaryCopyStringValue(globalDict, "Router"); ok && router != "" {
				if iface, ok := cfDictionaryCopyStringValue(globalDict, "PrimaryInterface"); ok && iface != "" {
					cfg := result[iface]
					if cfg.gateway == "" {
						cfg.gateway = router
					}
					if cfg.mode == IpModeNone {
						cfg.mode = IpModeDHCP
					}
					result[iface] = cfg
				}
			}
			releaseCF(globalValue)
		}
		releaseCF(CFTypeRef(globalRef))
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

func parseDarwinConfigMethod(method string) IpMode {
	switch strings.ToLower(method) {
	case "dhcp", "automatic", "bootps":
		return IpModeDHCP
	case "manual", "static":
		return IpModeStatic
	default:
		return IpModeNone
	}
}

func gatherCaptiveNetworkDetails() map[string]*darwinWiFiDetails {
	if !captiveNetworkReady || cnCopySupportedInterfaces == nil || cnCopyCurrentNetworkInfo == nil {
		return nil
	}
	arr := cnCopySupportedInterfaces()
	if arr == nil {
		return nil
	}
	defer releaseCF(CFTypeRef(arr))
	count := int(cfArrayGetCount(arr))
	if count == 0 {
		return nil
	}
	result := make(map[string]*darwinWiFiDetails, count)
	for i := 0; i < count; i++ {
		ifacePtr := cfArrayGetValueAtIndex(arr, CFIndex(i))
		if ifacePtr == nil {
			continue
		}
		ifaceRef := CFStringRef(ifacePtr)
		name := cfStringToGoString(ifaceRef)
		if name == "" {
			continue
		}
		info := cnCopyCurrentNetworkInfo(ifaceRef)
		if info == nil {
			continue
		}
		dict := CFDictionaryRef(info)
		detail := &darwinWiFiDetails{}
		if ssid, ok := cfDictionaryCopyStringValue(dict, "SSID"); ok && ssid != "" {
			detail.SSID = ssid
		}
		if sec, ok := cfDictionaryCopyStringValue(dict, "SecurityType"); ok && sec != "" {
			detail.Security = sec
		}
		if ch, ok := cfDictionaryCopyIntValue(dict, "Channel"); ok && ch != 0 {
			detail.Channel = ch
		}
		if freq, ok := cfDictionaryCopyIntValue(dict, "ChannelFrequency"); ok && freq != 0 {
			detail.Frequency = freq
		}
		releaseCF(CFTypeRef(info))
		if detail.isEmpty() {
			continue
		}
		result[name] = detail
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

func gatherInterfaceTypes() (map[string]interfaceCategory, error) {
	if err := ensureSystemConfiguration(); err != nil {
		return nil, err
	}
	arr := scNetworkInterfaceCopyAll()
	if arr == nil {
		return nil, fmt.Errorf("SCNetworkInterfaceCopyAll returned nil")
	}
	defer releaseCF(CFTypeRef(arr))
	count := int(cfArrayGetCount(arr))
	if count == 0 {
		return nil, fmt.Errorf("no interfaces reported")
	}
	result := make(map[string]interfaceCategory, count)
	for i := 0; i < count; i++ {
		elemPtr := cfArrayGetValueAtIndex(arr, CFIndex(i))
		if elemPtr == nil {
			continue
		}
		ifaceRef := SCNetworkInterfaceRef(elemPtr)
		nameRef := scNetworkInterfaceGetBSDName(ifaceRef)
		if nameRef == nil {
			continue
		}
		name := cfStringToGoString(nameRef)
		if name == "" {
			continue
		}
		typeRef := scNetworkInterfaceGetInterfaceType(ifaceRef)
		category := classifyInterfaceType(typeRef)
		if category == interfaceCategoryUnknown {
			category = interfaceCategoryEthernet
		}
		result[name] = category
	}
	return result, nil
}

func classifyInterfaceType(typeRef CFStringRef) interfaceCategory {
	if typeRef == nil {
		return interfaceCategoryUnknown
	}
	typeName := strings.ToLower(cfStringToGoString(typeRef))
	switch typeName {
	case "ieee80211":
		return interfaceCategoryWiFi
	case "ethernet":
		return interfaceCategoryEthernet
	}
	if strings.Contains(typeName, "wifi") || strings.Contains(typeName, "ieee802") {
		return interfaceCategoryWiFi
	}
	if typeName != "" {
		return interfaceCategoryEthernet
	}
	return interfaceCategoryUnknown
}

func buildDarwinInterface(iface net.Interface, mode IpMode, gateway string) (NetworkInterface, error) {
	ni := NetworkInterface{
		Device: iface.Name,
		Mac:    iface.HardwareAddr.String(),
		Mode:   mode,
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
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		ip := ipNet.IP
		var addrType NetworkAddressType
		var mask string
		if v4 := ip.To4(); v4 != nil {
			addrType = NetworkAddressTypeV4
			mask = ipv4MaskString(ipNet.Mask)
		} else if v6 := ip.To16(); v6 != nil {
			addrType = NetworkAddressTypeV6
			ones, _ := ipNet.Mask.Size()
			mask = fmt.Sprintf("%d", ones)
		} else {
			continue
		}
		ni.Addresses = append(ni.Addresses, NetworkAddress{Type: addrType, Address: ip.String(), SubnetMask: mask, Gateway: gateway})
	}
	if ni.Mode == IpModeNone && len(ni.Addresses) > 0 {
		ni.Mode = IpModeStatic
	}
	return ni, nil
}

func fetchDarwinWiFiDetails(name string, overrides map[string]*darwinWiFiDetails) *darwinWiFiDetails {
	details := &darwinWiFiDetails{}
	filled := false

	if store, err := newDynamicStore("netkit.wifi." + name); err == nil {
		defer releaseCF(CFTypeRef(store))
		if key, err := makeCFString("State:/Network/Interface/" + name + "/AirPort"); err == nil {
			defer releaseCF(CFTypeRef(key))
			if value := scDynamicStoreCopyValue(store, key); value != nil {
				defer releaseCF(value)
				if cfGetTypeID(value) == cfDictionaryTypeID {
					dict := CFDictionaryRef(value)
					if ssid, ok := cfDictionaryCopyStringValue(dict, "SSID_STR"); ok && ssid != "" {
						details.SSID = ssid
						filled = true
					}
					if details.SSID == "" {
						if ssid, ok := cfDictionaryCopyStringValue(dict, "SSID"); ok && ssid != "" {
							details.SSID = strings.TrimRight(ssid, "\x00")
							if details.SSID != "" {
								filled = true
							}
						}
					}
					for _, candidate := range []string{"SECURITY", "AUTH_MODE", "AUTH_80211_AUTHENTICATION", "AP_SECURITY", "AUTH_UPPER_AUTHENTICATION"} {
						if sec, ok := cfDictionaryCopyStringValue(dict, candidate); ok && sec != "" {
							details.Security = sec
							filled = true
							break
						}
					}
					if rssi, ok := cfDictionaryCopyIntValue(dict, "RSSI"); ok {
						details.RSSI = rssi
						filled = true
					} else if rssi, ok := cfDictionaryCopyIntValue(dict, "RSSI_AVG"); ok {
						details.RSSI = rssi
						filled = true
					}
					if rate, ok := cfDictionaryCopyIntValue(dict, "LINK_RATE"); ok {
						details.LinkRate = rate
						filled = true
					} else if rate, ok := cfDictionaryCopyIntValue(dict, "LINK_TX_RATE"); ok {
						details.LinkRate = rate
						filled = true
					}
					if width, ok := cfDictionaryCopyIntValue(dict, "CHANNEL_WIDTH"); ok {
						details.ChannelWidth = width
						filled = true
					}
					if channelRef, err := cfDictionaryCopyValue(dict, "CHANNEL"); err == nil && channelRef != nil && cfGetTypeID(channelRef) == cfDictionaryTypeID {
						chDict := CFDictionaryRef(channelRef)
						if ch, ok := cfDictionaryCopyIntValue(chDict, "CHANNEL"); ok {
							details.Channel = ch
							filled = true
						}
						if freq, ok := cfDictionaryCopyIntValue(chDict, "FREQUENCY"); ok {
							details.Frequency = freq
							filled = true
						}
						if width, ok := cfDictionaryCopyIntValue(chDict, "CHANNEL_WIDTH"); ok {
							details.ChannelWidth = width
						}
						if phy, ok := cfDictionaryCopyStringValue(chDict, "PHY"); ok && phy != "" {
							details.RadioType = phy
						}
					}
					if details.RadioType == "" {
						if phy, ok := cfDictionaryCopyStringValue(dict, "PHY_MODE"); ok && phy != "" {
							details.RadioType = phy
						}
					}
					if details.Frequency == 0 && details.RadioType != "" {
						details.Frequency = deriveFrequencyFromPHY(details.RadioType, details.Channel)
					}
					if details.Frequency == 0 && details.Channel != 0 {
						details.Frequency = channelToFrequency(details.Channel)
					}
				}
			}
		}
	}

	if extra := coreWLANWiFiDetails(name); extra != nil {
		details.merge(extra)
		filled = true
	}

	if overrides != nil {
		if override := overrides[name]; override != nil && !override.isEmpty() {
			details.merge(override)
			filled = true
		}
	}

	if !filled && details.isEmpty() {
		return nil
	}
	return details
}

func parseDarwinWiFiSecurity(value string) WlanSecurity {
	lower := strings.ToLower(value)
	switch {
	case strings.Contains(lower, "wpa3"):
		if strings.Contains(lower, "sae") {
			return WlanSecurityWPA3SAE
		}
		if strings.Contains(lower, "eap") || strings.Contains(lower, "enterprise") {
			return WlanSecurityWPA3EAP
		}
		return WlanSecurityWPA3SAE
	case strings.Contains(lower, "wpa2"):
		if strings.Contains(lower, "psk") || strings.Contains(lower, "personal") {
			return WlanSecurityWPA2
		}
		return WlanSecurityWPA2EAP
	case strings.Contains(lower, "wpa"):
		if strings.Contains(lower, "psk") || strings.Contains(lower, "personal") {
			return WlanSecurityWPA
		}
		return WlanSecurityWPAEAP
	case strings.Contains(lower, "owe"):
		return WlanSecurityOWE
	case strings.Contains(lower, "wep"):
		return WlanSecurityWEP
	case strings.Contains(lower, "open") || strings.Contains(lower, "none"):
		return WlanSecurityOpen
	default:
		return WlanSecurityUnknown
	}
}

func signalStrengthFromRSSI(rssi int32) SignalStrength {
	switch {
	case rssi >= -50:
		return SignalStrengthExcellent
	case rssi >= -60:
		return SignalStrengthGood
	case rssi >= -70:
		return SignalStrengthFair
	case rssi >= -80:
		return SignalStrengthWeak
	default:
		return SignalStrengthPoor
	}
}

func deriveFrequencyFromPHY(phy string, channel int) int {
	p := strings.ToLower(phy)
	switch {
	case strings.Contains(p, "6ghz"), strings.Contains(p, "6 ghz"), strings.Contains(p, "802.11be"), strings.Contains(p, "802.11ax6"), strings.Contains(p, "802.11ax (6"):
		if channel > 0 {
			return 5950 + channel*5
		}
		return 5950
	case strings.Contains(p, "5ghz"), strings.Contains(p, "5 ghz"), strings.Contains(p, "802.11a"), strings.Contains(p, "802.11ac"), strings.Contains(p, "802.11ax"):
		if channel > 0 {
			return 5000 + channel*5
		}
		return 5000
	case strings.Contains(p, "802.11b"), strings.Contains(p, "802.11g"), strings.Contains(p, "802.11n"), strings.Contains(p, "2.4"):
		return channelToFrequency(channel)
	default:
		if channel > 0 {
			return channelToFrequency(channel)
		}
		return 0
	}
}

func channelToFrequency(channel int) int {
	if channel <= 0 {
		return 0
	}
	if channel <= 14 {
		if channel == 14 {
			return 2484
		}
		return 2412 + (channel-1)*5
	}
	if channel >= 1 && channel <= 233 {
		// Attempt to differentiate 6 GHz based on extended range (> 180 typical for 5GHz upper channels)
		if channel >= 1 && channel <= 233 && channel < 30 {
			// Channels 1-29 in this branch likely 6GHz; bias to 6GHz baseline
			return 5950 + channel*5
		}
	}
	if channel >= 182 {
		return 5950 + (channel-182)*5
	}
	return 5000 + channel*5
}

func coreWLANWiFiDetails(name string) *darwinWiFiDetails {
	if !coreWLANReady || objc_getClass == nil || sel_registerName == nil || objc_msgSend == nil {
		return nil
	}
	var result *darwinWiFiDetails
	if runOnMainQueue(func() {
		result = coreWLANWiFiDetailsUnsafe(name)
	}) {
		return result
	}
	return coreWLANWiFiDetailsUnsafe(name)
}

func coreWLANWiFiDetailsUnsafe(name string) *darwinWiFiDetails {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	pool := nsAutoreleasePoolNew()
	if pool != nil {
		defer nsAutoreleasePoolDrain(pool)
	}
	clientClass := objcClass("CWWiFiClient")
	if clientClass == nil {
		return nil
	}
	sharedSel := objcSelector("sharedWiFiClient")
	if sharedSel == 0 {
		return nil
	}
	client := objc_msgSend(clientClass, sharedSel)
	if client == nil {
		return nil
	}
	iface := coreWLANFindInterface(client, name)
	if iface == nil {
		return nil
	}
	return coreWLANExtractDetails(iface)
}

func nsAutoreleasePoolNew() objcID {
	if objc_msgSend == nil {
		return nil
	}
	poolClass := objcClass("NSAutoreleasePool")
	if poolClass == nil {
		return nil
	}
	allocSel := objcSelector("alloc")
	initSel := objcSelector("init")
	if allocSel == 0 || initSel == 0 {
		return nil
	}
	pool := objc_msgSend(poolClass, allocSel)
	if pool == nil {
		return nil
	}
	return objc_msgSend(pool, initSel)
}

func nsAutoreleasePoolDrain(pool objcID) {
	if pool == nil || objc_msgSend == nil {
		return
	}
	if drainSel := objcSelector("drain"); drainSel != 0 {
		objc_msgSend(pool, drainSel)
		return
	}
	if releaseSel := objcSelector("release"); releaseSel != 0 {
		objc_msgSend(pool, releaseSel)
	}
}

func coreWLANFindInterface(client objcID, name string) objcID {
	if client == nil {
		return nil
	}
	if name != "" && objc_msgSend_objcID != nil {
		ifSel := objcSelector("interfaceWithName:")
		if ifSel != 0 {
			ifName := objcNSString(name)
			if ifName != nil {
				iface := objc_msgSend_objcID(client, ifSel, ifName)
				if iface != nil {
					return iface
				}
			}
		}
	}
	if interfaceSel := objcSelector("interface"); interfaceSel != 0 {
		iface := objc_msgSend(client, interfaceSel)
		if iface != nil {
			if name == "" {
				return iface
			}
			if strings.EqualFold(coreWLANInterfaceName(iface), name) {
				return iface
			}
		}
	}
	if interfacesSel := objcSelector("interfaces"); interfacesSel != 0 && objc_msgSend_int != nil && objc_msgSend_uintptr != nil {
		if arr := objc_msgSend(client, interfacesSel); arr != nil {
			countSel := objcSelector("count")
			getSel := objcSelector("objectAtIndex:")
			if countSel != 0 && getSel != 0 {
				count := int(objc_msgSend_int(arr, countSel))
				var fallback objcID
				for i := 0; i < count; i++ {
					iface := objc_msgSend_uintptr(arr, getSel, uintptr(i))
					if iface == nil {
						continue
					}
					if fallback == nil {
						fallback = iface
					}
					if name == "" {
						return iface
					}
					if strings.EqualFold(coreWLANInterfaceName(iface), name) {
						return iface
					}
				}
				if fallback != nil {
					return fallback
				}
			}
		}
	}
	return nil
}

func coreWLANInterfaceName(iface objcID) string {
	if iface == nil {
		return ""
	}
	if nameSel := objcSelector("interfaceName"); nameSel != 0 {
		if nameObj := objc_msgSend(iface, nameSel); nameObj != nil {
			return nsStringToGo(nameObj)
		}
	}
	return ""
}

func coreWLANExtractDetails(iface objcID) *darwinWiFiDetails {
	if iface == nil {
		return nil
	}
	details := &darwinWiFiDetails{}
	if ssidSel := objcSelector("ssid"); ssidSel != 0 {
		if ssidObj := objc_msgSend(iface, ssidSel); ssidObj != nil {
			details.SSID = nsStringToGo(ssidObj)
		}
	}
	if details.SSID == "" {
		if dataSel := objcSelector("ssidData"); dataSel != 0 {
			if dataObj := objc_msgSend(iface, dataSel); dataObj != nil {
				if lengthSel := objcSelector("length"); lengthSel != 0 && objc_msgSend_int != nil {
					length := int(objc_msgSend_int(dataObj, lengthSel))
					if length > 0 && objc_msgSend_char != nil {
						if bytesSel := objcSelector("bytes"); bytesSel != 0 {
							if ptr := objc_msgSend_char(dataObj, bytesSel); ptr != nil {
								data := unsafe.Slice((*byte)(ptr), length)
								details.SSID = strings.TrimRight(string(data), "\x00")
							}
						}
					}
				}
			}
		}
	}
	if rssiSel := objcSelector("rssiValue"); rssiSel != 0 && objc_msgSend_int != nil {
		details.RSSI = int(objc_msgSend_int(iface, rssiSel))
	}
	if channelSel := objcSelector("wlanChannel"); channelSel != 0 {
		if channelObj := objc_msgSend(iface, channelSel); channelObj != nil {
			if chanNumSel := objcSelector("channelNumber"); chanNumSel != 0 && objc_msgSend_int != nil {
				details.Channel = int(objc_msgSend_int(channelObj, chanNumSel))
			}
			if widthSel := objcSelector("channelWidth"); widthSel != 0 && objc_msgSend_int != nil {
				if width := objc_msgSend_int(channelObj, widthSel); width >= 0 {
					details.ChannelWidth = coreWLANChannelWidth(int(width))
				}
			}
		}
	}
	if txSel := objcSelector("transmitRate"); txSel != 0 && objc_msgSend_int != nil {
		if rate := objc_msgSend_int(iface, txSel); rate > 0 {
			details.LinkRate = int(rate)
		}
	}
	if secSel := objcSelector("security"); secSel != 0 && objc_msgSend_int != nil {
		details.Security = coreWLANSecurityString(objc_msgSend_int(iface, secSel))
	}
	if details.Frequency == 0 && details.Channel != 0 {
		details.Frequency = channelToFrequency(details.Channel)
	}
	return details
}

func coreWLANChannelWidth(code int) int {
	switch code {
	case 1:
		return 20
	case 2:
		return 40
	case 3:
		return 80
	case 4:
		return 160
	default:
		return 0
	}
}

func coreWLANSecurityString(code int64) string {
	switch code {
	case 0:
		return "open"
	case 1:
		return "wep"
	case 2, 3, 5, 6:
		return "wpa personal"
	case 4, 11:
		return "wpa2 personal"
	case 7, 8, 9, 10:
		return "wpa2 enterprise"
	case 12:
		return "wpa3 sae"
	case 13, 14, 15:
		return "wpa3 enterprise"
	default:
		return ""
	}
}

func objcClass(name string) objcID {
	if objc_getClass == nil || name == "" {
		return nil
	}
	bytes := append([]byte(name), 0)
	return objc_getClass(&bytes[0])
}

func objcSelector(name string) SEL {
	if sel_registerName == nil || name == "" {
		return 0
	}
	bytes := append([]byte(name), 0)
	return sel_registerName(&bytes[0])
}

func objcNSString(value string) objcID {
	if value == "" || objc_msgSend_ptr == nil {
		return nil
	}
	class := objcClass("NSString")
	if class == nil {
		return nil
	}
	sel := objcSelector("stringWithUTF8String:")
	if sel == 0 {
		return nil
	}
	bytes := append([]byte(value), 0)
	return objc_msgSend_ptr(class, sel, unsafe.Pointer(&bytes[0]))
}

func nsStringToGo(str objcID) string {
	if str == nil || objc_msgSend_char == nil {
		return ""
	}
	sel := objcSelector("UTF8String")
	if sel == 0 {
		return ""
	}
	ptr := objc_msgSend_char(str, sel)
	if ptr == nil {
		return ""
	}
	return cStringToGoString((*byte)(ptr))
}

func newDynamicStore(label string) (SCDynamicStoreRef, error) {
	if err := ensureSystemConfiguration(); err != nil {
		return nil, err
	}
	nameRef, err := makeCFString(label)
	if err != nil {
		return nil, err
	}
	defer releaseCF(CFTypeRef(nameRef))
	store := scDynamicStoreCreate(CFAllocatorRef(nil), nameRef, 0, 0)
	if store == nil {
		return nil, fmt.Errorf("SCDynamicStoreCreate failed")
	}
	return store, nil
}

func makeCFString(value string) (CFStringRef, error) {
	bytes := append([]byte(value), 0)
	ref := cfStringCreateWithCString(CFAllocatorRef(nil), &bytes[0], kCFStringEncodingUTF8)
	if ref == nil {
		return nil, fmt.Errorf("CFStringCreateWithCString failed")
	}
	return ref, nil
}

func cfDictionaryCopyValue(dict CFDictionaryRef, key string) (CFTypeRef, error) {
	keyRef, err := makeCFString(key)
	if err != nil {
		return nil, err
	}
	defer releaseCF(CFTypeRef(keyRef))
	var valuePtr unsafe.Pointer
	if cfDictionaryGetValueIfPresent(dict, unsafe.Pointer(keyRef), &valuePtr) == 0 {
		return nil, nil
	}
	return CFTypeRef(valuePtr), nil
}

func cfDictionaryCopyStringValue(dict CFDictionaryRef, key string) (string, bool) {
	valueRef, err := cfDictionaryCopyValue(dict, key)
	if err != nil || valueRef == nil {
		return "", false
	}
	typeID := cfGetTypeID(valueRef)
	switch typeID {
	case cfStringTypeID:
		return cfStringToGoString(CFStringRef(valueRef)), true
	case cfNumberTypeID:
		if cfNumberGetValue != nil {
			var raw int64
			if cfNumberGetValue(CFNumberRef(valueRef), kCFNumberSInt64Type, unsafe.Pointer(&raw)) != 0 {
				return strconv.FormatInt(raw, 10), true
			}
		}
	case cfDataTypeID:
		if data := cfDataToBytes(CFDataRef(valueRef)); len(data) > 0 {
			return string(data), true
		}
	}
	return "", false
}

func cfDictionaryCopyIntValue(dict CFDictionaryRef, key string) (int, bool) {
	valueRef, err := cfDictionaryCopyValue(dict, key)
	if err != nil || valueRef == nil {
		return 0, false
	}
	typeID := cfGetTypeID(valueRef)
	switch typeID {
	case cfNumberTypeID:
		if cfNumberGetValue != nil {
			var raw int64
			if cfNumberGetValue(CFNumberRef(valueRef), kCFNumberSInt64Type, unsafe.Pointer(&raw)) != 0 {
				return int(raw), true
			}
		}
	case cfStringTypeID:
		s := strings.TrimSpace(cfStringToGoString(CFStringRef(valueRef)))
		if s == "" {
			return 0, false
		}
		if v, err := strconv.Atoi(s); err == nil {
			return v, true
		}
	}
	return 0, false
}

func cfDataToBytes(ref CFDataRef) []byte {
	if ref == nil || cfDataGetLength == nil {
		return nil
	}
	length := int(cfDataGetLength(ref))
	if length <= 0 {
		return nil
	}
	if cfDataGetBytePtr != nil {
		ptr := cfDataGetBytePtr(ref)
		if ptr != nil {
			data := unsafe.Slice(ptr, length)
			return append([]byte(nil), data...)
		}
	}
	return nil
}

func cfDictionaryCopyStringArray(dict CFDictionaryRef, key string) ([]string, error) {
	valueRef, err := cfDictionaryCopyValue(dict, key)
	if err != nil || valueRef == nil {
		return nil, err
	}
	if cfGetTypeID(valueRef) != cfArrayTypeID {
		return nil, nil
	}
	arr := CFArrayRef(valueRef)
	count := int(cfArrayGetCount(arr))
	result := make([]string, 0, count)
	for i := 0; i < count; i++ {
		elemPtr := cfArrayGetValueAtIndex(arr, CFIndex(i))
		if elemPtr == nil {
			continue
		}
		elem := CFTypeRef(elemPtr)
		if cfGetTypeID(elem) != cfStringTypeID {
			continue
		}
		result = append(result, cfStringToGoString(CFStringRef(elem)))
	}
	return result, nil
}

func cfStringToGoString(ref CFStringRef) string {
	if ref == nil {
		return ""
	}
	if ptr := cfStringGetCStringPtr(ref, kCFStringEncodingUTF8); ptr != nil {
		return cStringToGoString(ptr)
	}
	length := cfStringGetLength(ref)
	if length == 0 {
		return ""
	}
	max := cfStringGetMaximumSizeForEncoding(length, kCFStringEncodingUTF8)
	bufLen := int(max) + 1
	if bufLen <= 0 {
		bufLen = int(length)*4 + 1
	}
	buf := make([]byte, bufLen)
	if len(buf) == 0 {
		buf = append(buf, 0)
	}
	if cfStringGetCString(ref, &buf[0], CFIndex(len(buf)), kCFStringEncodingUTF8) == 0 {
		return ""
	}
	if idx := bytes.IndexByte(buf, 0); idx >= 0 {
		buf = buf[:idx]
	}
	return string(buf)
}

func cStringToGoString(ptr *byte) string {
	if ptr == nil {
		return ""
	}
	const maxCStringLen = 1 << 30
	buf := (*[maxCStringLen]byte)(unsafe.Pointer(ptr))
	length := 0
	for length < maxCStringLen {
		if buf[length] == 0 {
			break
		}
		length++
	}
	if length == 0 {
		return ""
	}
	data := unsafe.Slice(ptr, length)
	result := string(data)
	runtime.KeepAlive(ptr) // ensure pointer remains valid until after the copy
	return result
}

func releaseCF(ref CFTypeRef) {
	if ref != nil && cfRelease != nil {
		cfRelease(ref)
	}
}

func readResolvConfNameservers(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var servers []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.HasPrefix(line, "nameserver") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			servers = append(servers, fields[1])
		}
	}
	return servers
}

func ipv4MaskString(mask net.IPMask) string {
	if len(mask) == 4 {
		return fmt.Sprintf("%d.%d.%d.%d", mask[0], mask[1], mask[2], mask[3])
	}
	return ""
}
