package connect

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"time"

	"github.com/Diniboy1123/usque/internal"
	"github.com/quic-go/quic-go/quicvarint"
	"golang.org/x/net/http2"
)

type HTTP2Connection struct {
	ctx  context.Context
	tr   *http2.Transport
	conn *http2.ClientConn

	reader *bufio.Reader
	writer io.WriteCloser
	buf    []byte
}

func (c *HTTP2Connection) ReadPacket(buf []byte) (int, error) {
	for {
		contextID, err := quicvarint.Read(c.reader)
		if err != nil {
			select {
			case <-c.ctx.Done():
				return 0, net.ErrClosed
			default:
				return 0, fmt.Errorf("failed to read context ID: %v", err)
			}
		}

		length, err := quicvarint.Read(c.reader)
		if err != nil {
			return 0, fmt.Errorf("failed to read packet length: %v", err)
		}

		_, err = io.ReadAtLeast(c.reader, buf[:length], int(length))
		if err != nil {
			return 0, fmt.Errorf("failed to read packet: %v", err)
		}

		if contextID == HTTPDatagramContextID {
			return int(length), nil
		}
		log.Printf("Skip invalid context ID: 0x%x", contextID)
	}
}

func (c *HTTP2Connection) WritePacket(buf []byte) ([]byte, error) {
	if err := CheckPacket(buf); err != nil {
		return ICMPForError(err, buf)
	}

	if cap(c.buf) < len(buf)+9 {
		c.buf = make([]byte, 0, len(buf)+9)
	}
	data := c.buf[:0]

	data = append(data, HTTPDatagramContextID)
	data = quicvarint.Append(data, uint64(len(buf)))
	data = append(data, buf...)

	_, err := c.writer.Write(data)
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

func (c *HTTP2Connection) Close() error {
	if c.conn != nil {
		c.conn.Shutdown(c.ctx)
	}

	if c.tr != nil {
		c.tr.CloseIdleConnections()
	}

	return nil
}

func ConnectHTTP2(
	ctx context.Context,
	tlsConfig *tls.Config,
	keepAlivePeriod time.Duration,
	connectURL *url.URL,
	endpoint netip.AddrPort,
) (HTTPConnection, error) {
	c := &HTTP2Connection{
		ctx: ctx,
		buf: make([]byte, 1289),
	}

	headers := http.Header{}
	headers.Set("User-Agent", "")
	headers.Add(internal.VersionHeader, internal.ConnectVersion)
	headers.Add(internal.ProtocolHeader, internal.ConnectProtocol)
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: keepAlivePeriod,
	}

	c.tr = &http2.Transport{
		TLSClientConfig:    tlsConfig,
		DisableCompression: true,
		AllowHTTP:          false,
	}
	reader, writer := io.Pipe()

	conn, err := tls.DialWithDialer(dialer, "tcp", endpoint.String(), c.tr.TLSClientConfig)
	if err != nil {
		if err, ok := err.(x509.CertificateInvalidError); ok && err.Reason == x509.NoValidChains {
			return c, fmt.Errorf("HTTP/2 tunnel not supported on this server: %v", err)
		}
		return c, fmt.Errorf("failed to dial tls connection: %w", err)
	}

	c.conn, err = c.tr.NewClientConn(conn)
	if err != nil {
		return c, fmt.Errorf("failed to initiate http2 connection: %w", err)
	}

	resp, err := c.conn.RoundTrip(&http.Request{
		Method:        http.MethodConnect,
		URL:           connectURL,
		Header:        headers,
		ContentLength: -1,
		Body:          reader,
	})
	if err != nil {
		if err.Error() == "remote error: tls: access denied" {
			return c, ErrLogin
		}
		return c, err
	}

	if resp.StatusCode != http.StatusOK {
		return c, fmt.Errorf("server responded code %s (%d)", resp.Status, resp.StatusCode)
	}

	c.reader = bufio.NewReader(resp.Body)
	c.writer = writer

	return c, nil
}
