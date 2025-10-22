package connect

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/quic-go/quic-go"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

type DatagramHopLimitExceeded struct {
	HopLimit int
}

func (e *DatagramHopLimitExceeded) Is(target error) bool {
	t, ok := target.(*DatagramHopLimitExceeded)
	return ok && e.HopLimit == t.HopLimit
}

func (e *DatagramHopLimitExceeded) Error() string {
	return fmt.Sprint("DATAGRAM Hop limit too small:", e.HopLimit)
}

func CheckPacket(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	switch version := ipVersion(b); version {
	default:
	case ipv4.Version:
		if len(b) < ipv4.HeaderLen {
			return nil
		}
		// Check TTL
		if b[8] <= 1 {
			return &DatagramHopLimitExceeded{int(b[8])}
		}
	case ipv6.Version:
		if len(b) < ipv6.HeaderLen {
			return nil
		}
		// Check HopLimit
		if b[7] <= 1 {
			return &DatagramHopLimitExceeded{int(b[7])}
		}
	}
	return nil
}

func ICMPForError(err error, data []byte) ([]byte, error) {
	switch e := err.(type) {
	case *DatagramHopLimitExceeded:
		icmp, err := composeICMPHopLimitExceededPacket(data)
		if err != nil {
			return nil, fmt.Errorf("failed to compose Hop Limit Exceeded ICMP message: %v", err)
		}
		return icmp, nil
	case *quic.DatagramTooLargeError:
		icmp, err := composeICMPTooLargePacket(data, int(e.MaxDatagramPayloadSize))
		if err != nil {
			return nil, fmt.Errorf("failed to compose Too Large Packet ICMP message: %v", err)
		}
		return icmp, nil
	default:
		return nil, err
	}
}

func ipVersion(b []byte) uint8 { return b[0] >> 4 }

func calculateIPv4Checksum(header []byte) uint16 {
	// add every 16-bit word in the header, skipping the checksum field (bytes 10 and 11)
	var sum uint32
	for i := 0; i < len(header); i += 2 {
		if i == 10 {
			continue // skip checksum field
		}
		sum += uint32(binary.BigEndian.Uint16(header[i : i+2]))
	}
	for (sum >> 16) > 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func composeIPv4ICMP(icmp []byte, source []byte, dest []byte) []byte {
	length := ipv4.HeaderLen + len(icmp)
	header := make([]byte, ipv4.HeaderLen, length)
	header[0] = ipv4.Version<<4 | ipv4.HeaderLen>>2                          // Version and Header Length
	binary.BigEndian.PutUint16(header[2:4], uint16(length))                  // Total Length
	header[8] = 64                                                           // TTL
	header[9] = 1                                                            // Protocol (ICMP)
	copy(header[12:16], source)                                              // Source IP
	copy(header[16:20], dest)                                                // Dest IP
	binary.BigEndian.PutUint16(header[10:12], calculateIPv4Checksum(header)) // Header Checksum
	return append(header, icmp...)
}

func composeIPv6ICMP(icmp []byte, source []byte, dest []byte) []byte {
	header := make([]byte, ipv6.HeaderLen, ipv6.HeaderLen+len(icmp))
	header[0] = ipv6.Version << 4                              // Version
	binary.BigEndian.PutUint16(header[4:6], uint16(len(icmp))) // Payload Length
	header[6] = 58                                             // Next Header (ICMPv6)
	header[7] = 64                                             // Hop Limit
	copy(header[8:24], source)                                 // Source IP
	copy(header[24:40], dest)                                  // Dest IP
	return append(header, icmp...)
}

func composeICMPTooLargePacket(packet []byte, mtu int) ([]byte, error) {
	if len(packet) == 0 {
		return nil, errors.New("empty packet")
	}

	switch v := ipVersion(packet); v {
	case ipv4.Version:
		if len(packet) < ipv4.HeaderLen {
			return nil, errors.New("IPv4 packet too short")
		}
		icmpMessage := &icmp.Message{
			Type: ipv4.ICMPTypeDestinationUnreachable,
			Code: 4, // fragmentation needed and DF set
			Body: &icmp.PacketTooBig{
				MTU:  mtu,
				Data: packet[:min(len(packet), ipv4.HeaderLen+8)],
			},
		}
		icmp, err := icmpMessage.Marshal(nil)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal ICMP message: %w", err)
		}
		return composeIPv4ICMP(icmp, packet[16:20], packet[12:16]), nil
	case ipv6.Version:
		if len(packet) < ipv6.HeaderLen {
			return nil, errors.New("IPv6 packet too short")
		}
		icmpMessage := &icmp.Message{
			Type: ipv6.ICMPTypePacketTooBig,
			Body: &icmp.PacketTooBig{
				MTU:  mtu,
				Data: packet[:min(len(packet), 1232)],
			},
		}
		psh := icmp.IPv6PseudoHeader(packet[24:40], packet[8:24])
		icmp, err := icmpMessage.Marshal(psh)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal ICMP message: %w", err)
		}
		return composeIPv6ICMP(icmp, packet[24:40], packet[8:24]), nil
	default:
		return nil, fmt.Errorf("unknown IP version: %d", v)
	}
}

func composeICMPHopLimitExceededPacket(packet []byte) ([]byte, error) {
	if len(packet) == 0 {
		return nil, errors.New("empty packet")
	}

	switch v := ipVersion(packet); v {
	case 4:
		if len(packet) < ipv4.HeaderLen {
			return nil, errors.New("IPv4 packet too short")
		}
		icmpMessage := &icmp.Message{
			Type: ipv4.ICMPTypeTimeExceeded,
			Code: 0, // Hop limit exceeded in transit
			Body: &icmp.TimeExceeded{
				Data: packet[:min(len(packet), ipv4.HeaderLen+8)],
			},
		}
		icmp, err := icmpMessage.Marshal(nil)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal ICMP message: %w", err)
		}
		return composeIPv4ICMP(icmp, packet[16:20], packet[12:16]), nil
	case 6:
		if len(packet) < ipv6.HeaderLen {
			return nil, errors.New("IPv6 packet too short")
		}
		icmpMessage := &icmp.Message{
			Type: ipv6.ICMPTypeTimeExceeded,
			Code: 0, // Hop limit exceeded in transit
			Body: &icmp.TimeExceeded{
				Data: packet[:min(len(packet), 1232)],
			},
		}
		psh := icmp.IPv6PseudoHeader(packet[24:40], packet[8:24])
		icmp, err := icmpMessage.Marshal(psh)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal ICMP message: %w", err)
		}
		return composeIPv6ICMP(icmp, packet[24:40], packet[8:24]), nil
	default:
		return nil, fmt.Errorf("unknown IP version: %d", v)
	}
}
