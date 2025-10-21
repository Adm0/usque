//go:build windows

package cmd

import (
	"fmt"
	"log"
	"net"

	"github.com/Diniboy1123/usque/api"
	"github.com/Diniboy1123/usque/config"
	"github.com/Diniboy1123/usque/internal"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/tun"
)

var longDescription = "Expose Warp as a native TUN device that accepts any IP traffic." +
	" Requires wintun.dll and administrator rights."

var (
	tunGUID = &windows.GUID{Data1: 0x52FF161B, Data2: 0x974F, Data3: 0x11F0, Data4: [8]byte{0xAB, 0xBE, 0x5E, 0xAC, 0x1D, 0x44, 0xE7, 0x8E}}
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

	luid, err := internal.AliasToLuid(t.name)
	if err != nil {
		return nil, fmt.Errorf("failed to get LUID: %v", err)
	}

	if t.ipv4 {
		err = internal.AddIpAddress(luid, net.ParseIP(config.AppConfig.IPv4))
		if err != nil {
			return nil, fmt.Errorf("failed to set IPv4 address: %v", err)
		}
		log.Println("IPv4 address set successfully:", config.AppConfig.IPv4)

		err = internal.SetMTU(luid, windows.AF_INET, t.mtu)
		if err != nil {
			return nil, fmt.Errorf("failed to set IPv4 MTU: %v", err)
		}
		log.Println("IPv4 MTU set successfully:", t.mtu)
	}

	if t.ipv6 {
		err = internal.AddIpAddress(luid, net.ParseIP(config.AppConfig.IPv6))
		if err != nil {
			return nil, fmt.Errorf("failed to set IPv6 address: %v", err)
		}
		log.Println("IPv6 address set successfully:", config.AppConfig.IPv6)

		err = internal.SetMTU(luid, windows.AF_INET6, t.mtu)
		if err != nil {
			return nil, fmt.Errorf("failed to set IPv6 MTU: %v", err)
		}
		log.Println("IPv6 MTU set successfully:", t.mtu)
	}

	return api.NewNetstackAdapter(dev), nil
}
