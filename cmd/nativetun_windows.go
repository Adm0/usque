//go:build windows

package cmd

import (
	"fmt"
	"log"
	"net"
	"syscall"

	"github.com/Diniboy1123/usque/api"
	"github.com/Diniboy1123/usque/config"
	"github.com/Diniboy1123/usque/internal"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/tun"
)

var longDescription = "Expose Warp as a native TUN device that accepts any IP traffic." +
	" Requires wintun.dll and administrator rights."

var (
	// Random generated GUID: 52FF161B-974F-11F0-ABBE-5EAC1D44E78E
	tunGUID = &windows.GUID{Data1: 0x52ff161b, Data2: 0x974f, Data3: 0x11f0, Data4: [8]byte{0xab, 0xbe, 0x5e, 0xac, 0x1d, 0x44, 0xe7, 0x8e}}
)

func (t *tunDevice) create() (api.TunnelDevice, error) {
	if t.name == "" {
		t.name = "usque"
	}

	dev, err := tun.CreateTUNWithRequestedGUID(t.name, tunGUID, t.mtu)
	if err != nil {
		return nil, err
	}

	t.name, err = dev.Name()
	if err != nil {
		return nil, err
	}

	luid := internal.AliasToLuid(t.name)

	if t.ipv4 {
		err = internal.AddIpAddress(
			luid,
			net.ParseIP(config.AppConfig.IPv4),
			net.CIDRMask(32, 32),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to set IPv4 address: %v", err)
		}
		log.Println("IPv4 address set successfully:", config.AppConfig.IPv4)

		err = internal.SetMTU(luid, syscall.AF_INET, t.mtu)
		if err != nil {
			return nil, fmt.Errorf("failed to set IPv4 MTU: %v", err)
		}
		log.Println("IPv4 MTU set successfully:", t.mtu)
	}

	if t.ipv6 {
		err = internal.AddIpAddress(
			luid,
			net.ParseIP(config.AppConfig.IPv6),
			net.CIDRMask(128, 128),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to set IPv6 address: %v", err)
		}
		log.Println("IPv6 address set successfully:", config.AppConfig.IPv4)

		err = internal.SetMTU(luid, syscall.AF_INET6, t.mtu)
		if err != nil {
			return nil, fmt.Errorf("failed to set IPv6 MTU: %v", err)
		}
		log.Println("IPv6 MTU set successfully:", t.mtu)
	}

	return api.NewNetstackAdapter(dev), nil
}
