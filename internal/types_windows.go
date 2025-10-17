//go:build windows

package internal

import (
	"net"
	"unsafe"

	"golang.org/x/sys/windows"
)

// SOCKADDR_INET union (ws2ipdef.h)
type SockAddrInet struct {
	Family uint16
	data   [26]byte
}

const (
	IpDadStatePreferred = 4
)

func (addr *SockAddrInet) IP() net.IP {
	switch addr.Family {
	case windows.AF_INET:
		var data = (*windows.RawSockaddrInet4)(unsafe.Pointer(addr))
		return net.IP(data.Addr[:])
	case windows.AF_INET6:
		var data = (*windows.RawSockaddrInet6)(unsafe.Pointer(addr))
		return net.IP(data.Addr[:])
	default:
		return nil
	}
}

func (addr *SockAddrInet) FromIP(ip net.IP) {
	if ip4 := ip.To4(); ip4 != nil {
		dest4 := (*windows.RawSockaddrInet4)(unsafe.Pointer(addr))
		dest4.Family = windows.AF_INET
		copy(dest4.Addr[:], ip4)
	} else if ip6 := ip.To16(); ip6 != nil {
		dest6 := (*windows.RawSockaddrInet6)(unsafe.Pointer(addr))
		dest6.Family = windows.AF_INET6
		copy(dest6.Addr[:], ip6)
	}
}

// MIB_UNICASTIPADDRESS_ROW structure (netioapi.h)
type MibUnicastIpAddressRow struct {
	Address            SockAddrInet
	_                  [4]byte
	InterfaceLuid      uint64 // IF_LUID
	InterfaceIndex     uint32 // IF_INDEX
	PrefixOrigin       uint32 // NL_PREFIX_ORIGIN
	SuffixOrigin       uint32 // NL_SUFFIX_ORIGIN
	ValidLifetime      uint32
	PreferredLifetime  uint32
	OnLinkPrefixLength uint8
	SkipAsSource       bool
	_                  [2]byte
	DadState           uint32 // NL_DAD_STATE
	ScopeId            uint32 // SCOPE_ID
	CreationTimeStamp  uint64
}

// MIB_IPINTERFACE_ROW structure (netioapi.h)
type MibIpInterfaceRow struct {
	Family                               uint16 // ADDRESS_FAMILY
	_                                    [6]byte
	InterfaceLuid                        uint64 // NET_LUID
	InterfaceIndex                       uint32 // NET_IFINDEX
	MaxReassemblySize                    uint32
	InterfaceIdentifier                  uint64
	MinRouterAdvertisementInterval       uint32
	MaxRouterAdvertisementInterval       uint32
	AdvertisingEnabled                   bool
	ForwardingEnabled                    bool
	WeakHostSend                         bool
	WeakHostReceive                      bool
	UseAutomaticMetric                   bool
	UseNeighborUnreachabilityDetection   bool
	ManagedAddressConfigurationSupported bool
	OtherStatefulConfigurationSupported  bool
	AdvertiseDefaultRoute                bool
	_                                    [3]byte
	RouterDiscoveryBehavior              uint32 // NL_ROUTER_DISCOVERY_BEHAVIOR
	DadTransmits                         uint32
	BaseReachableTime                    uint32
	RetransmitTime                       uint32
	PathMtuDiscoveryTimeout              uint32
	LinkLocalAddressBehavior             uint32 //NL_LINK_LOCAL_ADDRESS_BEHAVIOR
	LinkLocalAddressTimeout              uint32
	ZoneIndices                          [16]uint32
	SitePrefixLength                     uint32
	Metric                               uint32
	NlMtu                                uint32
	Connected                            bool
	SupportsWakeUpPatterns               bool
	SupportsNeighborDiscovery            bool
	SupportsRouterDiscovery              bool
	ReachableTime                        uint32
	TransmitOffload                      uint8 //NL_INTERFACE_OFFLOAD_ROD
	ReceiveOffload                       uint8 //NL_INTERFACE_OFFLOAD_ROD
	DisableDefaultRoutes                 bool
	_                                    [1]byte
}
