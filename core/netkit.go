package core

var globalNetkit Netkit

type Netkit interface {
	Hostname() (string, error)
	DNSServers() ([]string, error)
	LanInterfaces() ([]LanNetworkInterface, error)
	WlanInterfaces() ([]WlanNetworkInterface, error)
}

func GlobalNetKit() Netkit {
	if globalNetkit == nil {
		globalNetkit = DefaultNetkit()
	}
	return globalNetkit
}

func Hostname() (string, error) {
	return GlobalNetKit().Hostname()
}

func DNSServers() ([]string, error) {
	return GlobalNetKit().DNSServers()
}

func LanInterfaces() ([]LanNetworkInterface, error) {
	return GlobalNetKit().LanInterfaces()
}

func WlanInterfaces() ([]WlanNetworkInterface, error) {
	return GlobalNetKit().WlanInterfaces()
}

func Summary() (*NetworkState, error) {
	hostname, err := Hostname()
	if err != nil {
		return nil, err
	}
	dnsServers, err := DNSServers()
	if err != nil {
		return nil, err
	}
	lanIfaces, err := LanInterfaces()
	if err != nil {
		return nil, err
	}
	wlanIfaces, err := WlanInterfaces()
	if err != nil {
		return nil, err
	}
	return &NetworkState{
		Hostname:       hostname,
		DNSServers:     dnsServers,
		LanInterfaces:  lanIfaces,
		WlanInterfaces: wlanIfaces,
	}, nil
}
