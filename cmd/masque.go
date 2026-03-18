package cmd

import (
	"fmt"
	"log"
	"net/netip"
	"time"

	"github.com/Diniboy1123/usque/api"
	"github.com/Diniboy1123/usque/config"
	"github.com/Diniboy1123/usque/internal"
	"github.com/spf13/cobra"
)

func masqueCmd(cmd *cobra.Command) (*config.Masque, error) {
	sni, err := cmd.Flags().GetString("sni-address")
	if err != nil {
		return nil, fmt.Errorf("Failed to get SNI address: %v\n", err)
	}

	privKey, err := config.AppConfig.GetEcPrivateKey()
	if err != nil {
		return nil, fmt.Errorf("Failed to get private key: %v\n", err)
	}

	peerPubKey, err := config.AppConfig.GetEcEndpointPublicKey()
	if err != nil {
		return nil, fmt.Errorf("Failed to get public key: %v\n", err)
	}

	cert, err := internal.GenerateCert(privKey, &privKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("Failed to generate cert: %v\n", err)
	}

	tlsConfig, err := api.PrepareTlsConfig(privKey, peerPubKey, cert, sni)
	if err != nil {
		return nil, fmt.Errorf("Failed to prepare TLS config: %v\n", err)
	}

	connectPort, err := cmd.Flags().GetUint16("connect-port")
	if err != nil {
		return nil, fmt.Errorf("Failed to get connect port: %v\n", err)
	}

	var endpoint netip.Addr
	if ipv6, err := cmd.Flags().GetBool("ipv6"); err == nil && !ipv6 {
		endpoint, err = netip.ParseAddr(config.AppConfig.EndpointV4)
		if err != nil {
			return nil, fmt.Errorf("Failed to get endpoint: %s\n", err)
		}
	} else {
		endpoint, err = netip.ParseAddr(config.AppConfig.EndpointV6)
		if err != nil {
			return nil, fmt.Errorf("Failed to get endpoint: %s\n", err)
		}
	}

	mtu, err := cmd.Flags().GetInt("mtu")
	if err != nil {
		return nil, fmt.Errorf("Failed to get MTU: %v\n", err)
	}
	if mtu != 1280 {
		log.Println("Warning: MTU is not the default 1280. This is not supported. Packet loss and other issues may occur.")
	}

	var IPv4, IPv6 netip.Addr
	tunnelIPv4, err := cmd.Flags().GetBool("no-tunnel-ipv4")
	if err != nil {
		return nil, fmt.Errorf("Failed to get no tunnel IPv4: %v\n", err)
	}

	if !tunnelIPv4 {
		IPv4, err = netip.ParseAddr(config.AppConfig.IPv4)
		if err != nil {
			return nil, fmt.Errorf("Failed to parse IPv4 address: %v\n", err)
		}
	}

	tunnelIPv6, err := cmd.Flags().GetBool("no-tunnel-ipv6")
	if err != nil {
		return nil, fmt.Errorf("Failed to get no tunnel IPv6: %v\n", err)
	}

	if !tunnelIPv6 {
		IPv6, err = netip.ParseAddr(config.AppConfig.IPv6)
		if err != nil {
			return nil, fmt.Errorf("Failed to parse IPv6 address: %v\n", err)
		}
	}

	initialPacketSize, err := cmd.Flags().GetUint16("initial-packet-size")
	if err != nil {
		return nil, fmt.Errorf("Failed to get initial packet size: %v\n", err)
	}

	keepalivePeriod, err := cmd.Flags().GetDuration("keepalive-period")
	if err != nil {
		return nil, fmt.Errorf("Failed to get keepalive period: %v\n", err)
	}

	reconnectDelay, err := cmd.Flags().GetDuration("reconnect-delay")
	if err != nil {
		return nil, fmt.Errorf("Failed to get reconnect delay: %v\n", err)
	}

	return &config.Masque{
		TlsConfig:         tlsConfig,
		Endpoint:          netip.AddrPortFrom(endpoint, connectPort),
		Mtu:               mtu,
		IPv4:              IPv4,
		IPv6:              IPv6,
		InitialPacketSize: initialPacketSize,
		KeepalivePeriod:   keepalivePeriod,
		ReconnectDelay:    reconnectDelay,
	}, nil
}

func masqueInit(cmd *cobra.Command) {
	cmd.Flags().Uint16P("connect-port", "P", 443, "Used port for MASQUE connection")
	cmd.Flags().BoolP("ipv6", "6", false, "Use IPv6 for MASQUE connection")
	cmd.Flags().BoolP("no-tunnel-ipv4", "F", false, "Disable IPv4 inside the MASQUE tunnel")
	cmd.Flags().BoolP("no-tunnel-ipv6", "S", false, "Disable IPv6 inside the MASQUE tunnel")
	cmd.Flags().StringP("sni-address", "s", internal.ConnectSNI, "SNI address to use for MASQUE connection")
	cmd.Flags().DurationP("keepalive-period", "k", 30*time.Second, "Keepalive period for MASQUE connection")
	cmd.Flags().IntP("mtu", "m", 1280, "MTU for MASQUE connection")
	cmd.Flags().Uint16P("initial-packet-size", "i", 1242, "Initial packet size for MASQUE connection")
	cmd.Flags().DurationP("reconnect-delay", "r", 1*time.Second, "Delay between reconnect attempts")
}
