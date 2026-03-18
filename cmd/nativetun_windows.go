//go:build windows

package cmd

import (
	"fmt"

	"github.com/Diniboy1123/usque/api"
	"github.com/Diniboy1123/usque/internal"
	"golang.zx2c4.com/wireguard/tun"
)

var longDescription = "Expose Warp as a native TUN device that accepts any IP traffic." +
	" Requires wintun.dll and administrator rights."

func (t *tunDevice) create() (api.TunnelDevice, error) {
	if t.name == "" {
		t.name = "usque"
	}

	dev, err := tun.CreateTUNWithRequestedGUID(t.name, internal.NameToGuid(t.name), t.mtu)
	if err != nil {
		return nil, err
	}

	t.name, err = dev.Name()
	if err != nil {
		return nil, err
	}

	if t.ipv4.IsValid() {
		err = internal.SetIPv4Address(t.name, t.ipv4)
		if err != nil {
			return nil, fmt.Errorf("failed to set IPv4 address: %v", err)
		}

		err = internal.SetIPv4MTU(t.name, t.mtu)
		if err != nil {
			return nil, fmt.Errorf("failed to set IPv4 MTU: %v", err)
		}
	}

	if t.ipv6.IsValid() {
		err = internal.SetIPv6Address(t.name, t.ipv6)
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
