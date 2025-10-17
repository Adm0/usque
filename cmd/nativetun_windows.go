//go:build windows

package cmd

import (
	"fmt"
	"net"
	"syscall"

	"github.com/Diniboy1123/usque/api"
	"github.com/Diniboy1123/usque/config"
	"github.com/Diniboy1123/usque/internal"
	"golang.zx2c4.com/wireguard/tun"
)

var longDescription = "Expose Warp as a native TUN device that accepts any IP traffic." +
	" Requires wintun.dll and administrator rights."

func (t *tunDevice) create() (api.TunnelDevice, error) {
	if t.name == "" {
		t.name = "usque"
	}

	dev, err := tun.CreateTUN(t.name, t.mtu)
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

		err = internal.SetMTU(luid, syscall.AF_INET, t.mtu)
		if err != nil {
			return nil, fmt.Errorf("failed to set IPv4 MTU: %v", err)
		}
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

		err = internal.SetMTU(luid, syscall.AF_INET6, t.mtu)
		if err != nil {
			return nil, fmt.Errorf("failed to set IPv6 MTU: %v", err)
		}
	}

	return api.NewNetstackAdapter(dev), nil
}
