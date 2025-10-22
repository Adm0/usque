package connect

import "errors"

type HTTPConnection interface {
	// Reads a packet from the IP Connection and returns its contents.
	ReadPacket(buf []byte) (int, error)
	// Writes a packet to the device and return ICMP message.
	WritePacket(buf []byte) ([]byte, error)
	// Close connection.
	Close() error
}

const HTTPDatagramContextID = 0

var (
	ErrLogin = errors.New("login failed! Please double-check if your tls key and cert is enrolled in the Cloudflare Access service")
)
