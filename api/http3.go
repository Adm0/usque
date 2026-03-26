package api

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"

	connectip "github.com/Diniboy1123/connect-ip-go"
	"github.com/Diniboy1123/usque/config"
	"github.com/Diniboy1123/usque/internal"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
)

type HTTP3Tunnel struct {
	udpConn *net.UDPConn
	tr      *http3.Transport
	ipConn  *connectip.Conn
}

// ConnectHTTP3Tunnel establishes a QUIC connection and sets up a Connect-IP tunnel with the provided endpoint.
// Endpoint address is used to check whether the authentication/connection is successful or not.
// Requires modified connect-ip-go for now to support Cloudflare's non RFC compliant implementation.
//
// Parameters:
//   - ctx: context.Context - The QUIC TLS context.
//   - config: *config.Masque - The Masque configuration.
//
// Returns:
//   - api.Connection: The HTTP/3 connection instance.
//   - error: An error if the connection setup fails.
func ConnectHTTP3Tunnel(ctx context.Context, config *config.Masque) (IPTunnel, error) {
	conn := &HTTP3Tunnel{}
	var rsp *http.Response
	var err error

	log.Printf("[HTTP3] Establishing MASQUE connection to %s\n", config.Endpoint.String())

	if config.Endpoint.Addr().Is4() {
		conn.udpConn, err = net.ListenUDP("udp4", nil)
	} else {
		conn.udpConn, err = net.ListenUDP("udp6", nil)
	}
	if err != nil {
		return conn, err
	}

	conn.tr = &http3.Transport{
		EnableDatagrams: true,
		AdditionalSettings: map[uint64]uint64{
			// official client still sends this out as well, even though
			// it's deprecated, see https://datatracker.ietf.org/doc/draft-ietf-masque-h3-datagram/00/
			// SETTINGS_H3_DATAGRAM_00 = 0x0000000000000276
			// https://github.com/cloudflare/quiche/blob/7c66757dbc55b8d0c3653d4b345c6785a181f0b7/quiche/src/h3/frame.rs#L46
			0x276: 1,
		},
		DisableCompression: true,
	}

	quicConn, err := quic.Dial(
		ctx,
		conn.udpConn,
		net.UDPAddrFromAddrPort(config.Endpoint),
		config.TlsConfig,
		internal.DefaultQuicConfig(config.KeepalivePeriod, config.InitialPacketSize),
	)
	if err != nil {
		return conn, err
	}

	hconn := conn.tr.NewClientConn(quicConn)

	additionalHeaders := http.Header{
		"User-Agent": []string{""},
		"PQ-Enabled": []string{"false"},
	}

	template := uritemplate.MustNew(internal.ConnectURI)
	conn.ipConn, rsp, err = connectip.Dial(ctx, hconn, template, "cf-connect-ip", additionalHeaders, true)
	if err != nil {
		if err.Error() == "CRYPTO_ERROR 0x131 (remote): tls: access denied" {
			return conn, errors.New("login failed! Please double-check if your tls key and cert is enrolled in the Cloudflare Access service")
		}
		return conn, fmt.Errorf("failed to dial connect-ip: %v", err)
	}

	if rsp.StatusCode != 200 {
		return conn, fmt.Errorf("failed to send request: %s", rsp.Status)
	}

	log.Printf("[HTTP3] Connected to MASQUE server\n")
	return conn, nil
}

func (c *HTTP3Tunnel) WritePacket(b []byte) (icmp []byte, err error) {
	return c.ipConn.WritePacket(b)
}

func (c *HTTP3Tunnel) ReadPacket(b []byte) (n int, err error) {
	return c.ipConn.ReadPacket(b, true)
}

func (c *HTTP3Tunnel) Close() error {
	if c == nil {
		return nil
	}
	c.ipConn.Close()
	if c.udpConn != nil {
		c.udpConn.Close()
	}
	if c.tr != nil {
		c.tr.Close()
	}
	return nil
}
