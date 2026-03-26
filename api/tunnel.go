package api

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Diniboy1123/usque/config"
	"github.com/quic-go/quic-go/http3"
	"github.com/songgao/water"
	"golang.zx2c4.com/wireguard/tun"
)

// NetBuffer is a pool of byte slices with a fixed capacity.
// Helps to reduce memory allocations and improve performance.
// It uses a sync.Pool to manage the byte slices.
// The capacity of the byte slices is set when the pool is created.
type NetBuffer struct {
	capacity int
	buf      sync.Pool
}

// Get returns a byte slice from the pool.
func (n *NetBuffer) Get() []byte {
	return *(n.buf.Get().(*[]byte))
}

// Put places a byte slice back into the pool.
// It checks if the capacity of the byte slice matches the pool's capacity.
// If it doesn't match, the byte slice is not returned to the pool.
func (n *NetBuffer) Put(buf []byte) {
	if cap(buf) != n.capacity {
		return
	}
	n.buf.Put(&buf)
}

// NewNetBuffer creates a new NetBuffer with the specified capacity.
// The capacity must be greater than 0.
func NewNetBuffer(capacity int) *NetBuffer {
	if capacity <= 0 {
		panic("capacity must be greater than 0")
	}
	return &NetBuffer{
		capacity: capacity,
		buf: sync.Pool{
			New: func() interface{} {
				b := make([]byte, capacity)
				return &b
			},
		},
	}
}

// TunnelDevice abstracts a TUN device so that we can use the same tunnel-maintenance code
// regardless of the underlying implementation.
type TunnelDevice interface {
	// ReadPacket reads a packet from the device (using the given mtu) and returns its contents.
	ReadPacket(buf []byte) (int, error)
	// WritePacket writes a packet to the device.
	WritePacket(pkt []byte) error
	// Close tunnel device
	Close() error
}

// NetstackAdapter wraps a tun.Device (e.g. from netstack) to satisfy TunnelDevice.
type NetstackAdapter struct {
	dev             tun.Device
	tunnelBufPool   sync.Pool
	tunnelSizesPool sync.Pool
}

func (n *NetstackAdapter) ReadPacket(buf []byte) (int, error) {
	packetBufsPtr := n.tunnelBufPool.Get().(*[][]byte)
	sizesPtr := n.tunnelSizesPool.Get().(*[]int)

	defer func() {
		(*packetBufsPtr)[0] = nil
		n.tunnelBufPool.Put(packetBufsPtr)
		n.tunnelSizesPool.Put(sizesPtr)
	}()

	(*packetBufsPtr)[0] = buf
	(*sizesPtr)[0] = 0

	_, err := n.dev.Read(*packetBufsPtr, *sizesPtr, 0)
	if err != nil {
		return 0, err
	}

	return (*sizesPtr)[0], nil
}

func (n *NetstackAdapter) WritePacket(pkt []byte) error {
	// Write expects a slice of packet buffers.
	_, err := n.dev.Write([][]byte{pkt}, 0)
	return err
}

func (n *NetstackAdapter) Close() error {
	return n.dev.Close()
}

// NewNetstackAdapter creates a new NetstackAdapter.
func NewNetstackAdapter(dev tun.Device) TunnelDevice {
	return &NetstackAdapter{
		dev: dev,
		tunnelBufPool: sync.Pool{
			New: func() interface{} {
				buf := make([][]byte, 1)
				return &buf
			},
		},
		tunnelSizesPool: sync.Pool{
			New: func() interface{} {
				sizes := make([]int, 1)
				return &sizes
			},
		},
	}
}

// WaterAdapter wraps a *water.Interface so it satisfies TunnelDevice.
type WaterAdapter struct {
	iface *water.Interface
}

func (w *WaterAdapter) ReadPacket(buf []byte) (int, error) {
	n, err := w.iface.Read(buf)
	if err != nil {
		return 0, err
	}

	return n, nil
}

func (w *WaterAdapter) WritePacket(pkt []byte) error {
	_, err := w.iface.Write(pkt)
	return err
}

func (w *WaterAdapter) Close() error {
	return w.iface.Close()
}

// NewWaterAdapter creates a new WaterAdapter.
func NewWaterAdapter(iface *water.Interface) TunnelDevice {
	return &WaterAdapter{iface: iface}
}

type IPTunnel interface {
	WritePacket(b []byte) (icmp []byte, err error)
	ReadPacket(b []byte) (n int, err error)
	Close() error
}

// MaintainTunnel continuously connects to the MASQUE server, then starts two
// forwarding goroutines: one forwarding from the device to the IP connection (and handling
// any ICMP reply), and the other forwarding from the IP connection to the device.
// If an error occurs in either loop, the connection is closed and a reconnect is attempted.
//
// Parameters:
//   - ctx: context.Context - The context for the connection.
//   - config: *config.Masque - The masque configuration.
func MaintainTunnel(ctx context.Context, config *config.Masque, device TunnelDevice) {
	packetBufferPool := NewNetBuffer(config.Mtu)
	closeChan := make(chan error, 1)
	defer close(closeChan)
	for {
		conn, err := ConnectHTTP3Tunnel(ctx, config)
		if err != nil {
			log.Printf("[HTTP3] Failed to connect tunnel: %v", err)
			conn.Close()
			time.Sleep(config.ReconnectDelay)
			continue
		}

		errChan := make(chan error, 2)

		go func() {
			for {
				buf := packetBufferPool.Get()
				n, err := device.ReadPacket(buf)
				if err != nil {
					if errors.Is(err, os.ErrClosed) {
						closeChan <- err
						packetBufferPool.Put(buf)
						return
					}
					packetBufferPool.Put(buf)
					errChan <- fmt.Errorf("failed to read from TUN device: %v", err)
					return
				}
				icmp, err := conn.WritePacket(buf[:n])
				if err != nil {
					packetBufferPool.Put(buf)
					if errors.Is(err, net.ErrClosed) {
						errChan <- fmt.Errorf("connection closed while writing to IP connection: %v", err)
						return
					}
					log.Printf("Error writing to IP connection: %v, continuing...", err)
					continue
				}
				packetBufferPool.Put(buf)

				if len(icmp) > 0 {
					if err := device.WritePacket(icmp); err != nil {
						if errors.Is(err, os.ErrClosed) {
							closeChan <- err
							return
						}
						log.Printf("Error writing ICMP to TUN device: %v, continuing...", err)
					}
				}
			}
		}()

		go func() {
			buf := packetBufferPool.Get()
			defer packetBufferPool.Put(buf)
			for {
				n, err := conn.ReadPacket(buf)
				if err != nil {
					if errors.Is(err, net.ErrClosed) {
						errChan <- fmt.Errorf("connection closed while reading from IP connection: %v", err)
						return
					}
					log.Printf("Error reading from IP connection: %v, continuing...", err)
					continue
				}
				if err := device.WritePacket(buf[:n]); err != nil {
					if errors.Is(err, os.ErrClosed) {
						closeChan <- err
						return
					}
					errChan <- fmt.Errorf("failed to write to TUN device: %v", err)
					return
				}
			}
		}()

		select {
		case err = <-errChan:
			log.Printf("Tunnel connection lost: %v. Reconnecting...", err)
			conn.Close()
			close(errChan)
			time.Sleep(config.ReconnectDelay)
			continue
		case err = <-closeChan:
			conn.Close()
			close(errChan)
			return
		case <-ctx.Done():
			conn.Close()
			close(errChan)
			return
		}
	}
}

// PrepareTlsConfig creates a TLS configuration using the provided certificate and SNI (Server Name Indication).
// It also verifies the peer's public key against the provided public key.
//
// Parameters:
//   - peerPubKey: *crypto.PublicKey - The endpoint's public key to pin to.
//   - cert: *tls.Certificate - The certificate chain to use for TLS authentication.
//   - sni: string - The Server Name Indication (SNI) to use.
//
// Returns:
//   - *tls.Config: A TLS configuration for secure communication.
//   - error: An error if TLS setup fails.
func PrepareTlsConfig(peerPubKey crypto.PublicKey, cert *tls.Certificate, sni string) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{
			*cert,
		},
		ServerName: sni,
		NextProtos: []string{http3.NextProtoH3},
		// WARN: SNI is usually not for the endpoint, so we must skip verification
		InsecureSkipVerify: true,
		// we pin to the endpoint public key
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			for index, rawCert := range rawCerts {
				cert, err := x509.ParseCertificate(rawCert)
				if err != nil {
					log.Printf("Failed to parse peer certificate #%d: %v", index+1, err)
					continue
				}
				if time.Now().Before(cert.NotBefore) || time.Now().After(cert.NotAfter) {
					log.Printf("Peer certificate #%d expired", index+1)
					goto err
				}

				switch cert.PublicKeyAlgorithm {
				case x509.ECDSA:
					if !cert.PublicKey.(*ecdsa.PublicKey).Equal(peerPubKey) {
						log.Printf("Peer certificate #%d has a different public key", index+1)
						goto err
					}
					return nil
				default:
					log.Printf("Peer certificate #%d has unsupported public key algorithm: %s", index+1, cert.PublicKeyAlgorithm)
					goto err
				}
			err:
				log.Printf("Certificate #%d:", index+1)
				log.Printf("    Version: %d", cert.Version)
				log.Printf("    Serial Number:  %x", cert.SerialNumber)
				log.Printf("    Signature Algorithm: %s", cert.SignatureAlgorithm)
				log.Printf("    Issuer: %s", cert.Issuer)
				log.Printf("    Not Before: %s", cert.NotBefore)
				log.Printf("    Not After : %s", cert.NotAfter)
				log.Printf("    Subject: %s", cert.Subject)
				log.Printf("    DnsNames: %s", strings.Join(cert.DNSNames, ", "))
			}

			return x509.CertificateInvalidError{
				Cert:   nil,
				Reason: x509.NoValidChains,
				Detail: "peer certificates don't contains valid public key.\n",
			}
		},
		CurvePreferences: []tls.CurveID{
			tls.CurveP256,
			tls.CurveP384,
			tls.CurveP521,
		},
		CipherSuites: []uint16{
			tls.TLS_AES_256_GCM_SHA384,
		},
	}

	return tlsConfig, nil
}
