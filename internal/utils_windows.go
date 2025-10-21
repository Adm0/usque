//go:build windows

package internal

import (
	"net"
	"syscall"
)

func AddIpAddress(luid uint64, ip net.IP) error {
	var address = &MibUnicastIpAddressRow{}
	InitializeUnicastIpAddressEntry(address)
	address.Address.SetIP(ip)
	address.InterfaceLuid = luid
	address.DadState = IpDadStatePreferred
	return CreateUnicastIpAddressEntry(address)
}

func SetMTU(luid uint64, family int, mtu int) error {
	entry := &MibIpInterfaceRow{}
	entry.Family = uint16(family)
	entry.InterfaceLuid = luid
	GetIpInterfaceEntry(entry)
	if entry.Family == syscall.AF_INET {
		entry.SitePrefixLength = 0
	}
	entry.NlMtu = uint32(mtu)
	return SetIpInterfaceEntry(entry)
}
