//go:build windows
// +build windows

package core

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const ifTypeIEEE80211 = 71

type WindowsNetkit struct{}

func DefaultNetkit() Netkit { return NewWindowsNetkit() }

func NewWindowsNetkit() *WindowsNetkit { return &WindowsNetkit{} }

// IP_ADDR_STRING mirrors the Windows linked list used by GetAdaptersInfo.
type ipAddrString struct {
	Next      uintptr
	IpAddress [16]byte
	IpMask    [16]byte
	Context   uint32
}

// ipAdapterInfo maps to IP_ADAPTER_INFO from iphlpapi.
type ipAdapterInfo struct {
	Next                *ipAdapterInfo
	ComboIndex          uint32
	AdapterName         [260]byte
	Description         [132]byte
	AddressLength       uint32
	Address             [8]byte
	Index               uint32
	Type                uint32
	DhcpEnabled         uint32
	CurrentIpAddress    uintptr
	IpAddressList       ipAddrString
	GatewayList         ipAddrString
	DhcpServer          ipAddrString
	HaveWins            uint32
	PrimaryWinsServer   ipAddrString
	SecondaryWinsServer ipAddrString
	LeaseObtained       int64
	LeaseExpires        int64
}

type adapterList struct {
	buf []byte
}

func newAdapterList() (*adapterList, error) {
	buf, err := loadAdaptersInfo()
	if err != nil {
		return nil, err
	}
	return &adapterList{buf: buf}, nil
}

func (a *adapterList) forEach(fn func(*ipAdapterInfo) bool) {
	if a == nil || len(a.buf) == 0 {
		return
	}
	for adapter := (*ipAdapterInfo)(unsafe.Pointer(&a.buf[0])); adapter != nil; adapter = nextAdapter(adapter) {
		if fn(adapter) {
			return
		}
	}
}

func (a *adapterList) findByInterface(iface net.Interface) *ipAdapterInfo {
	if a == nil {
		return nil
	}
	var match *ipAdapterInfo
	a.forEach(func(adapter *ipAdapterInfo) bool {
		if matchAdapter(adapter, iface) {
			match = adapter
			return true
		}
		return false
	})
	return match
}

func (a *adapterList) isWireless(iface net.Interface) bool {
	adapter := a.findByInterface(iface)
	return adapter != nil && adapter.Type == ifTypeIEEE80211
}

func (a *adapterList) usesDHCP(iface net.Interface) bool {
	adapter := a.findByInterface(iface)
	return adapter != nil && adapter.DhcpEnabled != 0
}

func (a *adapterList) gatewayForInterface(iface net.Interface) string {
	if a == nil {
		return ""
	}
	if adapter := a.findByInterface(iface); adapter != nil {
		if gw := adapterGateway(adapter); gw != "" {
			return gw
		}
	}
	return ""
}

func adapterGateway(adapter *ipAdapterInfo) string {
	if adapter == nil {
		return ""
	}
	gatewayRaw := string(adapter.GatewayList.IpAddress[:clen(adapter.GatewayList.IpAddress[:])])
	gateway := strings.TrimSpace(gatewayRaw)
	if gateway == "" || gateway == "0.0.0.0" {
		return ""
	}
	if net.ParseIP(gateway) == nil {
		return ""
	}
	return gateway
}

func (p *WindowsNetkit) Hostname() (string, error) { return os.Hostname() }

func (p *WindowsNetkit) DNSServers() ([]string, error) { return getDNSServers() }

func (p *WindowsNetkit) LanInterfaces() ([]LanNetworkInterface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	adapters, err := newAdapterList()
	if err != nil {
		adapters = nil
	}

	var lan []LanNetworkInterface
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if adapters != nil && adapters.isWireless(iface) {
			continue
		}

		ni, err := buildWindowsInterface(iface, adapters)
		if err != nil {
			continue
		}
		lan = append(lan, LanNetworkInterface{Interface: ni})
	}

	return lan, nil
}

func (p *WindowsNetkit) WlanInterfaces() ([]WlanNetworkInterface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	adapters, err := newAdapterList()
	if err != nil {
		adapters = nil
	}

	wifiInfo, _ := getWindowsWiFiInfo()
	var wlan []WlanNetworkInterface

	for _, iface := range ifaces {
		isWireless := false
		if adapters != nil {
			isWireless = adapters.isWireless(iface)
		} else {
			isWireless = looksWirelessByName(iface.Name)
		}
		if !isWireless {
			continue
		}

		ni, err := buildWindowsInterface(iface, adapters)
		if err != nil {
			continue
		}

		w := WlanNetworkInterface{Interface: ni, Security: WlanSecurityUnknown}
		if wifiInfo != nil {
			w.SSID = wifiInfo.SSID
			w.Security = parseWindowsWiFiSecurity(wifiInfo.Security)
			if ch := wifiInfo.channelNumber(); ch > 0 {
				w.Channel = int32(ch)
			}
			if freq := deriveFrequencyFromRadio(wifiInfo.RadioType); freq != 0 {
				w.Frequency = freq
			}
			if rate := wifiInfo.transmitRateValue(); rate > 0 {
				w.LinkSpeedTx = int32(rate + 0.5)
			}
			if quality := wifiInfo.signalQualityPercent(); quality >= 0 {
				rssi := qualityToRSSI(quality)
				w.SignalStrengthUnfiltered = int32(rssi)
				w.SignalStrength = rssiToSignalStrength(int32(rssi))
			}
		}

		wlan = append(wlan, w)
	}

	return wlan, nil
}

func buildWindowsInterface(iface net.Interface, adapters *adapterList) (NetworkInterface, error) {
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

	gateway := ""
	if adapters != nil {
		gateway = adapters.gatewayForInterface(iface)
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

	if adapters != nil && adapters.usesDHCP(iface) {
		ni.Mode = IpModeDHCP
	} else if len(ni.Addresses) > 0 {
		ni.Mode = IpModeStatic
	}

	return ni, nil
}

func looksWirelessByName(name string) bool {
	n := strings.ToLower(name)
	return strings.Contains(n, "wi-fi") || strings.Contains(n, "wifi") || strings.HasPrefix(n, "wlan")
}

// WiFiInfo reflects the helper output used in the poc implementation and keeps extra fields for numeric parsing.
type WiFiInfo struct {
	SSID         string
	Signal       string
	ReceiveRate  string
	TransmitRate string
	Channel      string
	RadioType    string
	Security     string

	signalQuality    uint32
	channelNum       uint32
	receiveRateMbps  float64
	transmitRateMbps float64
}

func (w *WiFiInfo) signalQualityPercent() int {
	if w == nil {
		return -1
	}
	if w.signalQuality > 0 {
		return int(w.signalQuality)
	}
	trimmed := strings.TrimSuffix(strings.TrimSpace(w.Signal), "%")
	if trimmed == "" {
		return -1
	}
	value, err := strconv.Atoi(trimmed)
	if err != nil {
		return -1
	}
	return value
}

func (w *WiFiInfo) channelNumber() int {
	if w == nil {
		return 0
	}
	if w.channelNum > 0 {
		return int(w.channelNum)
	}
	value, err := strconv.Atoi(strings.TrimSpace(w.Channel))
	if err != nil {
		return 0
	}
	return value
}

func (w *WiFiInfo) transmitRateValue() float64 {
	if w == nil {
		return 0
	}
	if w.transmitRateMbps > 0 {
		return w.transmitRateMbps
	}
	trimmed := strings.TrimSuffix(strings.TrimSpace(w.TransmitRate), "(Mbps)")
	trimmed = strings.TrimSuffix(strings.TrimSpace(trimmed), "Mbps")
	value, err := strconv.ParseFloat(strings.TrimSpace(trimmed), 64)
	if err != nil {
		return 0
	}
	return value
}

func getWindowsWiFiInfo() (*WiFiInfo, error) {
	wlanapi := windows.NewLazySystemDLL("wlanapi.dll")
	wlanOpenHandle := wlanapi.NewProc("WlanOpenHandle")
	wlanEnumInterfaces := wlanapi.NewProc("WlanEnumInterfaces")
	wlanQueryInterface := wlanapi.NewProc("WlanQueryInterface")
	wlanCloseHandle := wlanapi.NewProc("WlanCloseHandle")
	wlanFreeMemory := wlanapi.NewProc("WlanFreeMemory")

	var negotiatedVersion uint32
	var clientHandle uintptr
	ret, _, _ := wlanOpenHandle.Call(
		uintptr(2),
		0,
		uintptr(unsafe.Pointer(&negotiatedVersion)),
		uintptr(unsafe.Pointer(&clientHandle)),
	)
	if ret != 0 {
		return nil, fmt.Errorf("WlanOpenHandle failed: %v", ret)
	}
	defer wlanCloseHandle.Call(clientHandle, 0)

	var interfaceListPtr unsafe.Pointer
	ret, _, _ = wlanEnumInterfaces.Call(clientHandle, 0, uintptr(unsafe.Pointer(&interfaceListPtr)))
	if ret != 0 {
		return nil, fmt.Errorf("WlanEnumInterfaces failed: %v", ret)
	}
	defer wlanFreeMemory.Call(uintptr(interfaceListPtr))

	numInterfaces := *(*uint32)(interfaceListPtr)
	if numInterfaces == 0 {
		return nil, fmt.Errorf("no WiFi interfaces found")
	}

	const interfaceInfoOffset = uintptr(8)
	interfaceInfoPtr := unsafe.Add(interfaceListPtr, interfaceInfoOffset)
	interfaceGUID := (*windows.GUID)(interfaceInfoPtr)

	const wlanIntfOpcodeCurrentConnection = 7
	var dataSize uint32
	var attrPtr unsafe.Pointer
	var valueType uint32

	ret, _, _ = wlanQueryInterface.Call(
		clientHandle,
		uintptr(unsafe.Pointer(interfaceGUID)),
		uintptr(wlanIntfOpcodeCurrentConnection),
		0,
		uintptr(unsafe.Pointer(&dataSize)),
		uintptr(unsafe.Pointer(&attrPtr)),
		uintptr(unsafe.Pointer(&valueType)),
	)
	if ret != 0 {
		return nil, fmt.Errorf("not connected to WiFi or WlanQueryInterface failed: %v", ret)
	}
	defer wlanFreeMemory.Call(uintptr(attrPtr))

	type dot11Ssid struct {
		Length uint32
		SSID   [32]byte
	}

	type wlanAssociationAttributes struct {
		Dot11Ssid     dot11Ssid
		Dot11BssType  uint32
		Dot11Bssid    [6]byte
		_             [2]byte
		Dot11PhyType  uint32
		Dot11PhyIndex uint32
		SignalQuality uint32
		RxRate        uint32
		TxRate        uint32
	}

	type wlanSecurityAttributes struct {
		SecurityEnabled uint32
		OneXEnabled     uint32
		AuthAlgorithm   uint32
		CipherAlgorithm uint32
	}

	type wlanConnectionAttributes struct {
		InterfaceState uint32
		ConnectionMode uint32
		ProfileName    [256]uint16
		Association    wlanAssociationAttributes
		Security       wlanSecurityAttributes
	}

	conn := (*wlanConnectionAttributes)(attrPtr)

	info := &WiFiInfo{}
	ssidLen := conn.Association.Dot11Ssid.Length
	if ssidLen > 0 && ssidLen <= uint32(len(conn.Association.Dot11Ssid.SSID)) {
		info.SSID = string(conn.Association.Dot11Ssid.SSID[:ssidLen])
	}

	info.signalQuality = conn.Association.SignalQuality
	info.Signal = fmt.Sprintf("%d%%", info.signalQuality)
	info.receiveRateMbps = float64(conn.Association.RxRate) * 0.5
	info.transmitRateMbps = float64(conn.Association.TxRate) * 0.5
	info.ReceiveRate = fmt.Sprintf("%.1f (Mbps)", info.receiveRateMbps)
	info.TransmitRate = fmt.Sprintf("%.1f (Mbps)", info.transmitRateMbps)

	switch conn.Association.Dot11PhyType {
	case 1:
		info.RadioType = "802.11a"
	case 2:
		info.RadioType = "802.11b"
	case 3:
		info.RadioType = "802.11g"
	case 4:
		info.RadioType = "802.11n"
	case 7:
		info.RadioType = "802.11ac"
	case 8:
		info.RadioType = "802.11ax (WiFi 6)"
	default:
		info.RadioType = fmt.Sprintf("Unknown (%d)", conn.Association.Dot11PhyType)
	}

	if conn.Security.SecurityEnabled == 0 {
		info.Security = "Open"
	} else {
		switch conn.Security.AuthAlgorithm {
		case 1:
			info.Security = "Open"
		case 2:
			info.Security = "WPA"
		case 3:
			info.Security = "WPA_PSK"
		case 4:
			info.Security = "WPA2"
		case 5:
			info.Security = "WPA2_PSK"
		case 6:
			info.Security = "WPA3"
		case 7:
			info.Security = "WPA3_SAE"
		case 8:
			info.Security = "WPA3_Enterprise"
		default:
			if conn.Security.CipherAlgorithm == 4 {
				info.Security = "WEP"
			} else {
				info.Security = "Unknown"
			}
		}
	}

	const wlanIntfOpcodeChannelNumber = 8
	var channelDataSize uint32
	var channelPtr unsafe.Pointer
	ret, _, _ = wlanQueryInterface.Call(
		clientHandle,
		uintptr(unsafe.Pointer(interfaceGUID)),
		uintptr(wlanIntfOpcodeChannelNumber),
		0,
		uintptr(unsafe.Pointer(&channelDataSize)),
		uintptr(unsafe.Pointer(&channelPtr)),
		uintptr(unsafe.Pointer(&valueType)),
	)
	if ret == 0 && channelPtr != nil {
		info.channelNum = *(*uint32)(channelPtr)
		info.Channel = fmt.Sprintf("%d", info.channelNum)
		wlanFreeMemory.Call(uintptr(channelPtr))
	}

	if info.SSID == "" {
		return nil, fmt.Errorf("no active WiFi connection found")
	}

	return info, nil
}

func parseWindowsWiFiSecurity(security string) WlanSecurity {
	security = strings.ToLower(security)
	if strings.Contains(security, "wpa3") {
		if strings.Contains(security, "sae") {
			return WlanSecurityWPA3SAE
		}
		if strings.Contains(security, "enterprise") {
			return WlanSecurityWPA3EAP
		}
		return WlanSecurityWPA3SAE
	}
	if strings.Contains(security, "wpa2") {
		if strings.Contains(security, "psk") {
			return WlanSecurityWPA2
		}
		return WlanSecurityWPA2EAP
	}
	if strings.Contains(security, "wpa_psk") || (strings.Contains(security, "wpa") && strings.Contains(security, "psk")) {
		return WlanSecurityWPA
	}
	if strings.Contains(security, "wpa") {
		return WlanSecurityWPAEAP
	}
	if strings.Contains(security, "wep") {
		return WlanSecurityWEP
	}
	if strings.Contains(security, "open") {
		return WlanSecurityOpen
	}
	return WlanSecurityUnknown
}

func qualityToRSSI(percent int) int {
	if percent < 0 {
		return 0
	}
	if percent > 100 {
		percent = 100
	}
	return -100 + (percent * 70 / 100)
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

func deriveFrequencyFromRadio(radio string) int32 {
	r := strings.ToLower(radio)
	switch {
	case strings.Contains(r, "802.11a"), strings.Contains(r, "802.11ac"), strings.Contains(r, "802.11ax"):
		return 5000
	case strings.Contains(r, "802.11b"), strings.Contains(r, "802.11g"), strings.Contains(r, "802.11n"):
		return 2400
	default:
		return 0
	}
}

func ipv4MaskString(m net.IPMask) string {
	if len(m) == 4 {
		return fmt.Sprintf("%d.%d.%d.%d", m[0], m[1], m[2], m[3])
	}
	return ""
}

func clen(b []byte) int {
	for i, c := range b {
		if c == 0 {
			return i
		}
	}
	return len(b)
}

func loadAdaptersInfo() ([]byte, error) {
	iphlpapi := windows.NewLazySystemDLL("iphlpapi.dll")
	getAdaptersInfo := iphlpapi.NewProc("GetAdaptersInfo")

	var size uint32
	ret, _, _ := getAdaptersInfo.Call(0, uintptr(unsafe.Pointer(&size)))
	if ret != uintptr(windows.ERROR_BUFFER_OVERFLOW) && ret != 0 {
		return nil, fmt.Errorf("GetAdaptersInfo size failed: %v", ret)
	}

	buffer := make([]byte, size)
	ret, _, _ = getAdaptersInfo.Call(
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(unsafe.Pointer(&size)),
	)
	if ret != 0 {
		return nil, fmt.Errorf("GetAdaptersInfo failed: %v", ret)
	}

	return buffer, nil
}

func nextAdapter(cur *ipAdapterInfo) *ipAdapterInfo {
	if cur == nil {
		return nil
	}
	return cur.Next
}

func matchAdapter(adapter *ipAdapterInfo, iface net.Interface) bool {
	if adapter == nil || adapter.AddressLength == 0 || len(iface.HardwareAddr) == 0 {
		return false
	}

	mac := adapter.Address[:adapter.AddressLength]
	return adapter.AddressLength == uint32(len(iface.HardwareAddr)) && bytes.Equal(mac, iface.HardwareAddr)
}

func getDNSServers() ([]string, error) {
	key, err := registry.OpenKey(
		registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces`,
		registry.QUERY_VALUE|registry.ENUMERATE_SUB_KEYS,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to open registry key: %w", err)
	}
	defer key.Close()

	subkeys, err := key.ReadSubKeyNames(0)
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate subkeys: %w", err)
	}

	seen := make(map[string]bool)
	var servers []string

	for _, name := range subkeys {
		subKey, err := registry.OpenKey(
			registry.LOCAL_MACHINE,
			`SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\`+name,
			registry.QUERY_VALUE,
		)
		if err != nil {
			continue
		}

		collect := func(raw string) {
			entries := strings.FieldsFunc(raw, func(r rune) bool { return r == ' ' || r == ',' })
			for _, entry := range entries {
				entry = strings.TrimSpace(entry)
				if entry == "" {
					continue
				}
				if net.ParseIP(entry) == nil {
					continue
				}
				if !seen[entry] {
					servers = append(servers, entry)
					seen[entry] = true
				}
			}
		}

		if value, _, err := subKey.GetStringValue("NameServer"); err == nil && value != "" {
			collect(value)
		}
		if value, _, err := subKey.GetStringValue("DhcpNameServer"); err == nil && value != "" {
			collect(value)
		}

		subKey.Close()
	}

	if len(servers) == 0 {
		return nil, fmt.Errorf("no DNS servers found")
	}

	return servers, nil
}
