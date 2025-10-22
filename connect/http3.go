package connect

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"

	"github.com/Diniboy1123/usque/internal"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
)

// official client still sends this out as well, even though
// it's deprecated, see https://datatracker.ietf.org/doc/draft-ietf-masque-h3-datagram/00/
// SETTINGS_H3_DATAGRAM_00 = 0x0000000000000276
// https://github.com/cloudflare/quiche/blob/7c66757dbc55b8d0c3653d4b345c6785a181f0b7/quiche/src/h3/frame.rs#L46
const SETTINGS_H3_DATAGRAM_00 = 0x276

type HTTP3Connection struct {
	ctx       context.Context
	udpConn   *net.UDPConn
	transport *http3.Transport
	conn      *http3.RequestStream
	buf       []byte
}

func (c *HTTP3Connection) ReadPacket(buf []byte) (int, error) {
	for {
		data, err := c.conn.ReceiveDatagram(c.ctx)
		if err != nil {
			select {
			case <-c.ctx.Done():
				return 0, net.ErrClosed
			default:
			}
			e, ok := err.(*http3.Error)
			if ok && e.ErrorCode == http3.ErrCodeNoError {
				continue
			}
			return 0, err
		}
		contextID, n, err := quicvarint.Parse(data)
		if err != nil {
			return 0, fmt.Errorf("malformed datagram: %w", err)
		}
		if contextID == HTTPDatagramContextID {
			return copy(buf, data[n:]), err
		}
	}
}

func (c *HTTP3Connection) WritePacket(buf []byte) ([]byte, error) {
	if err := CheckPacket(buf); err != nil {
		return ICMPForError(err, buf)
	}

	if cap(c.buf) < len(buf)+1 {
		c.buf = make([]byte, len(buf)+1)
	}
	data := c.buf[:0]

	data = append(data, HTTPDatagramContextID)
	data = append(data, buf...)

	err := c.conn.SendDatagram(data)
	if err != nil {
		select {
		case <-c.ctx.Done():
			return nil, net.ErrClosed
		default:
			return ICMPForError(err, buf)
		}
	}
	return nil, nil
}

func (c *HTTP3Connection) Close() error {
	if c.conn != nil {
		c.conn.Close()
	}
	if c.transport != nil {
		c.transport.Close()
	}
	if c.udpConn != nil {
		c.udpConn.Close()
	}
	return nil
}

// ConnectHTTP3 establishes a HTTP/3 connection and sets up a tunnel with the provided endpoint.
// Endpoint address is used to check whether the authentication/connection is successful or not.
//
// Parameters:
//   - ctx: context.Context - The goroutine context for connection.
//   - tlsConfig: *tls.Config - The TLS configuration for secure communication.
//   - quicConfig: *quic.Config - The QUIC configuration settings.
//   - connectUrl: url.URL - The URL for the initial request.
//   - endpoint: *netip.AddrPort - The address of the QUIC server.
//
// Returns:
//   - *HTTP3Connection: The HTTP/3 connection instance.
//   - error: An error if the connection setup fails.
func ConnectHTTP3(
	ctx context.Context,
	tlsConfig *tls.Config,
	quicConfig *quic.Config,
	connectURL *url.URL,
	endpoint netip.AddrPort,
) (HTTPConnection, error) {
	var err error
	c := &HTTP3Connection{
		ctx: ctx,
	}

	c.transport = &http3.Transport{
		TLSClientConfig: tlsConfig,
		QUICConfig:      quicConfig,
		EnableDatagrams: true,
		AdditionalSettings: map[uint64]uint64{
			SETTINGS_H3_DATAGRAM_00: 1,
		},
		DisableCompression: true,
	}

	c.udpConn, err = net.ListenUDP("udp", nil)
	if err != nil {
		return c, fmt.Errorf("failed to open socket: %w", err)
	}

	quicConn, err := quic.Dial(
		ctx,
		c.udpConn,
		net.UDPAddrFromAddrPort(endpoint),
		c.transport.TLSClientConfig,
		c.transport.QUICConfig,
	)
	if err != nil {
		return c, fmt.Errorf("failed to dial QUIC connection: %w", err)
	}

	conn := c.transport.NewClientConn(quicConn)

	select {
	case <-ctx.Done():
		return c, context.Cause(ctx)
	case <-conn.Context().Done():
		return c, context.Cause(conn.Context())
	case <-conn.ReceivedSettings():
	}

	settings := conn.Settings()
	if !settings.EnableDatagrams {
		return c, errors.New("server didn't enable datagrams")
	}
	if !settings.EnableExtendedConnect {
		return c, errors.New("server didn't enable Extended CONNECT")
	}

	c.conn, err = conn.OpenRequestStream(ctx)
	if err != nil {
		return c, fmt.Errorf("failed to open request stream: %w", err)
	}

	headers := http.Header{}
	headers.Set("User-Agent", "")
	headers.Set(internal.VersionHeader, internal.ConnectVersion)
	if err := c.conn.SendRequestHeader(&http.Request{
		Method: http.MethodConnect,
		Proto:  internal.ConnectProtocol,
		Host:   connectURL.Host,
		Header: headers,
		URL:    connectURL,
	}); err != nil {
		return c, fmt.Errorf("failed to send request: %w", err)
	}

	rsp, err := c.conn.ReadResponse()
	if err != nil {
		if err, ok := err.(*quic.TransportError); ok && err.ErrorCode == 0x131 {
			return c, errors.New("login failed! Please double-check if your tls key and cert is enrolled in the Cloudflare Access service")
		}
		return c, fmt.Errorf("failed to read response: %w", err)
	}
	if rsp.StatusCode != http.StatusOK {
		return c, fmt.Errorf("server responded with %s (%d)", rsp.Status, rsp.StatusCode)
	}
	return c, nil
}
