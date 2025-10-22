package api

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/Diniboy1123/usque/connect"
	"github.com/Diniboy1123/usque/internal"
	"github.com/quic-go/quic-go"
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
	// Reads a packet from the device (using the given mtu) and returns its contents.
	ReadPacket(buf []byte) (int, error)
	// Writes a packet to the device.
	WritePacket(pkt []byte) error
	// Сloses the tunnel device.
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

// MaintainTunnel continuously connects to the MASQUE server, then starts two
// forwarding goroutines: one forwarding from the device to the IP connection (and handling
// any ICMP reply), and the other forwarding from the IP connection to the device.
// If an error occurs in either loop, the connection is closed and a reconnect is attempted.
//
// Parameters:
//   - ctx: context.Context - The context for the connection.
//   - tlsConfig: *tls.Config - The TLS configuration for secure communication.
//   - quicConfig: *quic.Config - The QUIC configuration settings.
//   - endpoint: netip.AddrPort - The address of the MASQUE server.
//   - device: TunnelDevice - The TUN device to forward packets to and from.
//   - mtu: int - The MTU of the TUN device.
//   - reconnectDelay: time.Duration - The delay between reconnect attempts.
func MaintainTunnel(
	ctx context.Context,
	tlsConfig *tls.Config,
	quicConfig *quic.Config,
	endpoint netip.AddrPort,
	device TunnelDevice,
	mtu int,
	reconnectDelay time.Duration,
	http3 bool,
	http2 bool,
) {
	packetBufferPool := NewNetBuffer(mtu)

	url, err := url.Parse(internal.ConnectURI)
	if err != nil {
		log.Printf("Failed to parse connect URI %s: %v", internal.ConnectURI, err)
		os.Exit(1)
	}

	for {
		log.Printf("Establishing MASQUE connection to %s", endpoint.String())
		var ipConn connect.HTTPConnection
		if http3 {
			ipConn, err = connect.ConnectHTTP3(
				ctx,
				tlsConfig,
				quicConfig,
				url,
				endpoint,
			)
			if err == nil {
				goto connected
			}
			ipConn.Close()
			if errors.Is(err, context.Canceled) {
				return
			}
			log.Printf("Failed to connect HTTP/3 tunnel: %v", err)
		}
		if http2 {
			ipConn, err = connect.ConnectHTTP2(
				ctx,
				tlsConfig,
				quicConfig.KeepAlivePeriod,
				url,
				endpoint,
			)
			if err == nil {
				goto connected
			}
			ipConn.Close()
			if errors.Is(err, context.Canceled) {
				return
			}
			log.Printf("Failed to connect HTTP/2 tunnel: %v", err)
		}
		time.Sleep(reconnectDelay)
		continue

	connected:
		log.Println("Connected to MASQUE server")
		errChan := make(chan error, 2)
		closeChan := make(chan error, 2)

		go func() {
			for {
				buf := packetBufferPool.Get()
				n, err := device.ReadPacket(buf)
				if err != nil {
					packetBufferPool.Put(buf)
					if errors.Is(err, os.ErrClosed) {
						closeChan <- fmt.Errorf("connection closed while reading from TUN device: %v", err)
						return
					}
					errChan <- fmt.Errorf("failed to read from TUN device: %v", err)
					return
				}
				icmp, err := ipConn.WritePacket(buf[:n])
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
							closeChan <- fmt.Errorf("connection closed while writing ICMP to TUN device: %v", err)
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
				n, err := ipConn.ReadPacket(buf)
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
						closeChan <- fmt.Errorf("connection closed while writing to TUN device: %v", err)
						return
					}
					errChan <- fmt.Errorf("failed to write to TUN device: %v", err)
					return
				}
			}
		}()

		select {
		case <-ctx.Done():
			log.Printf("Close connection...")
			ipConn.Close()
			return
		case err = <-errChan:
			log.Printf("Tunnel connection lost: %v. Reconnecting...", err)
			ipConn.Close()
			time.Sleep(reconnectDelay)
		case err = <-closeChan:
			log.Printf("Tunnel device closed: %v. Aborting...", err)
			ipConn.Close()
			os.Exit(0)
		}
	}
}
