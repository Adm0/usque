package config

import (
	"crypto/tls"
	"net/netip"
	"time"
)

type Masque struct {
	TlsConfig         *tls.Config    // The TLS configuration for secure communication.
	Endpoint          netip.AddrPort // The address with port of the MASQUE server.
	Mtu               int            // The MTU of the TUN device.
	IPv4              netip.Addr     // Assigned IPv4 address
	IPv6              netip.Addr     // Assigned IPv6 address
	InitialPacketSize uint16         // The initial packet size for the QUIC connection.
	KeepalivePeriod   time.Duration  // The keepalive period for the QUIC connection.
	ReconnectDelay    time.Duration  // The delay between reconnect attempts.
}
