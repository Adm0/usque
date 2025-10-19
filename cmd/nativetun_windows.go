//go:build windows

package cmd

import (
	"fmt"

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

	if t.ipv4 {
		err = internal.SetIPv4Address(t.name, config.AppConfig.IPv4, "255.255.255.255")
		if err != nil {
			return nil, fmt.Errorf("failed to set IPv4 address: %v", err)
		}

		err = internal.SetIPv4MTU(t.name, t.mtu)
		if err != nil {
			return nil, fmt.Errorf("failed to set IPv4 MTU: %v", err)
		}
	}

	if t.ipv6 {
		err = internal.SetIPv6Address(t.name, config.AppConfig.IPv6, "128")
		if err != nil {
			return nil, fmt.Errorf("failed to set IPv6 address: %v", err)
		}

		err = internal.SetIPv6MTU(t.name, t.mtu)
		if err != nil {
			return nil, fmt.Errorf("failed to set IPv6 MTU: %v", err)
		}
	}

	return api.NewNetstackAdapter(dev), nil
}
