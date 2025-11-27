package core

// An address configured on a network device
// NetworkAddressType represents the address type (IPv4 or IPv6).
type NetworkAddressType int32

const (
	NetworkAddressTypeNone NetworkAddressType = iota
	NetworkAddressTypeV4
	NetworkAddressTypeV6
)

// NetworkAddress holds address configuration.
type NetworkAddress struct {
	// type of the address (ipv4 or ipv6)
	Type NetworkAddressType `json:"type"`
	// ipv4 or ipv6 address
	Address string `json:"address"`
	// subnet mask of the address e.g. "255.255.255.0"(ipv4) or "64"(ipv6)
	SubnetMask string `json:"subnet_mask"`
	// gateway of the address
	Gateway string `json:"gateway"`
}

// A physical or logical network device

// IpMode represents IP acquisition mode.
type IpMode int32

const (
	IpModeNone IpMode = iota
	IpModeDHCP
	IpModeStatic
)

// ConnectionStatus represents connection state of the interface.
type ConnectionStatus int32

const (
	ConnectionStatusNone ConnectionStatus = iota
	ConnectionStatusConnecting
	ConnectionStatusUnconnected
	ConnectionStatusConnected
)

// NetworkInterface describes a network interface.
type NetworkInterface struct {
	// device name of the network interface e.g. eth0, wlan0
	Device string `json:"device"`
	// mac address of the network interface
	Mac string `json:"mac"`
	// ip mode of the network interface
	Mode IpMode `json:"mode"`
	// connection status of the network interface
	ConnectionStatus ConnectionStatus `json:"connection_status"`
	// network addresses of the network interface
	Addresses []NetworkAddress `json:"addresses"`
}

type LanNetworkInterface struct {
	Interface NetworkInterface `json:"interface"`
}

// WlanSecurity represents Wi-Fi security type.
type WlanSecurity int32

const (
	WlanSecurityUnknown WlanSecurity = iota
	WlanSecurityOpen
	WlanSecurityWEP
	WlanSecurityWPA
	WlanSecurityWPA2
	WlanSecurityWPAEAP
	WlanSecurityWPA2EAP
	WlanSecurityWPA3SAE
	WlanSecurityWPA3H2E
	WlanSecurityWPA3EAP
	WlanSecurityOWE
)

// SignalStrength represents Wi-Fi signal strength category.
type SignalStrength int32

const (
	SignalStrengthUnknown   SignalStrength = iota
	SignalStrengthPoor                     // below -80dBm
	SignalStrengthWeak                     // -71dBm to -80dBm
	SignalStrengthFair                     // -61dBm to -70dBm
	SignalStrengthGood                     // -51dBm to -60dBm
	SignalStrengthExcellent                // -30dBm to -50dBm
)

type WlanNetworkInterface struct {
	Interface NetworkInterface `json:"interface"`
	Security  WlanSecurity     `json:"security"`
	// ssid of the wlan network
	SSID string `json:"ssid"`
	// signal strength of the wlan network
	SignalStrength SignalStrength `json:"signal_strength"`
	// channel of the wlan network
	Channel int32 `json:"channel"`
	// Frequency (MHz)
	Frequency int32 `json:"frequency"`
	// Bandwidth of channel (MHz)
	ChannelWidth int32 `json:"channel_width"`
	// Link speed tx (Mbit/s)
	LinkSpeedTx int32 `json:"link_speed_tx"`
	// unfiltered (no average) signal strength of wlan network
	SignalStrengthUnfiltered int32 `json:"signal_strength_unfiltered"`
}

// Current state of all network interfaces
// Device Code: Maintained by framework & host interface
type NetworkState struct {
	// hostname of the device
	Hostname string `json:"hostname"`
	// dns servers of the network interface
	DNSServers []string `json:"dns_servers"`
	// all lan network interfaces
	LanInterfaces []LanNetworkInterface `json:"lan_interfaces"`
	// all wlan network interfaces
	WlanInterfaces []WlanNetworkInterface `json:"wlan_interfaces"`
}

// Configured NTP servers
// Device Code: Maintained by framework & host interface
type NtpConfiguration struct {
	// List of NTP servers. Format "hostname:port". E.g. "time.google.com:123"
	NtpServers []string `json:"ntp_servers"`
}
