package connect

type HTTPConnection interface {
	// Reads a packet from the IP Connection and returns its contents.
	ReadPacket(buf []byte) (int, error)
	// Writes a packet to the device and return ICMP message.
	WritePacket(buf []byte) ([]byte, error)
	// Close connection.
	Close() error
}

const HTTPDatagramContextID = 0
