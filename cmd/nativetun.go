package cmd

import (
	"context"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"syscall"

	"github.com/Diniboy1123/usque/api"
	"github.com/Diniboy1123/usque/config"
	"github.com/Diniboy1123/usque/internal"
	"github.com/spf13/cobra"
)

type tunDevice struct {
	name     string
	mtu      int
	iproute2 bool
	ipv4     netip.Prefix
	ipv6     netip.Prefix
}

var nativeTunCmd = &cobra.Command{
	Use:   "nativetun",
	Short: "Expose Warp as a native TUN device",
	Long:  longDescription,
	Run: func(cmd *cobra.Command, args []string) {
		if !config.ConfigLoaded {
			cmd.Println("Config not loaded. Please register first.")
			return
		}

		masqueConfig, err := masqueCmd(cmd)
		if err != nil {
			cmd.PrintErr(err)
			return
		}

		setIproute2, err := cmd.Flags().GetBool("no-iproute2")
		if err != nil {
			cmd.Printf("Failed to get no set address: %v\n", err)
			return
		}

		interfaceName, err := cmd.Flags().GetString("interface-name")
		if err != nil {
			cmd.Printf("Failed to get interface name: %v\n", err)
			return
		}

		if interfaceName != "" {
			err = internal.CheckIfname(interfaceName)
			if err != nil {
				log.Printf("Invalid interface name: %v", err)
				return
			}
		}

		t := &tunDevice{
			name:     interfaceName,
			mtu:      masqueConfig.Mtu,
			iproute2: !setIproute2,
			ipv4:     netip.PrefixFrom(masqueConfig.IPv4, 32),
			ipv6:     netip.PrefixFrom(masqueConfig.IPv6, 128),
		}

		dev, err := t.create()
		if err != nil {
			log.Println("Are you root/administrator? TUN device creation usually requires elevated privileges.")
			log.Fatalf("Failed to create TUN device: %v", err)
		}
		defer dev.Close()

		log.Printf("Created TUN device: %s", t.name)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		go api.MaintainTunnel(ctx, masqueConfig, dev)

		log.Println("Tunnel established, you may now set up routing and DNS")

		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)

		select {
		case <-ctx.Done():
		case <-sigChan:
		}

		signal.Stop(sigChan)
		close(sigChan)
	},
}

func init() {
	nativeTunCmd.Flags().BoolP("no-iproute2", "I", false, "Linux only: Do not set up IP addresses and do not set the link up")
	nativeTunCmd.Flags().StringP("interface-name", "n", "", "Custom inteface name for the TUN interface")
	masqueInit(nativeTunCmd)
	rootCmd.AddCommand(nativeTunCmd)
}
