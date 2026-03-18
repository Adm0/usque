//go:build windows

package internal

import (
	"fmt"
	"log"
	"net/netip"
	"os/exec"
)

func SetIPv4Address(ifaceName string, ipNet netip.Prefix) error {
	cmd := exec.Command("netsh", "interface", "ipv4", "set", "address",
		fmt.Sprintf("name=\"%s\"", ifaceName),
		"static", ipNet.String())

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s", output)
	}

	log.Println("IPv4 address set successfully:", ipNet.String())
	return nil
}

func SetIPv6Address(ifaceName string, ipNet netip.Prefix) error {
	cmd := exec.Command("netsh", "interface", "ipv6", "set", "address",
		fmt.Sprintf("interface=\"%s\"", ifaceName),
		ipNet.String())

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s", output)
	}

	log.Println("IPv6 address set successfully:", ipNet.String())
	return nil
}

func SetIPv4MTU(ifaceName string, mtu int) error {
	cmd := exec.Command("netsh", "interface", "ipv4", "set", "subinterface",
		fmt.Sprintf("\"%s\"", ifaceName),
		fmt.Sprintf("mtu=%d", mtu))

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s", output)
	}

	log.Println("IPv4 MTU set successfully:", mtu)
	return nil
}

func SetIPv6MTU(ifaceName string, mtu int) error {
	cmd := exec.Command("netsh", "interface", "ipv6", "set", "subinterface",
		fmt.Sprintf("\"%s\"", ifaceName),
		fmt.Sprintf("mtu=%d", mtu))

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s", output)
	}

	log.Println("IPv6 MTU set successfully:", mtu)
	return nil
}
