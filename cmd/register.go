package cmd

import (
	"encoding/base64"
	"fmt"
	"log"
	"net/netip"
	"os"
	"strings"

	"github.com/Diniboy1123/usque/api"
	"github.com/Diniboy1123/usque/config"
	"github.com/Diniboy1123/usque/internal"
	"github.com/spf13/cobra"
)

var registerCmd = &cobra.Command{
	Use:   "register",
	Short: "Register a new client and enroll a device key",
	Long: "Registers a new account and enrolls a device key. Also makes sure that it switches to" +
		" MASQUE mode. Saves the config to a file.",
	Run: func(cmd *cobra.Command, args []string) {
		if config.ConfigLoaded {
			fmt.Printf("You already have a config. Do you want to overwrite it? (y/N) ")
			var response string
			if _, err := fmt.Scanln(&response); err != nil {
				log.Fatalf("Failed to read response: %v", err)
			}
			if !strings.EqualFold(response, "y") {
				return
			}
		}

		acceptTos, err := cmd.Flags().GetBool("accept-tos")
		if err != nil {
			log.Fatalf("Failed to get accept-tos flag: %v", err)
		}

		if !acceptTos {
			fmt.Print("You must accept the Terms of Service (https://www.cloudflare.com/application/terms/) to register. Do you agree? (y/n): ")
			var response string
			if _, err := fmt.Scanln(&response); err != nil {
				log.Fatalf("failed to read user input: %v", err)
			}
			if !strings.EqualFold(response, "y") {
				log.Fatalf("user did not accept TOS")
			}
		}

		configPath, err := cmd.Flags().GetString("config")
		if err != nil {
			log.Fatalf("Failed to get config path: %v", err)
		}
		if configPath == "" {
			log.Fatalf("Config path is required")
		}

		deviceName, err := cmd.Flags().GetString("name")
		if err != nil {
			log.Fatalf("Failed to get device name: %v", err)
		}

		model, err := cmd.Flags().GetString("model")
		if err != nil {
			log.Fatalf("Failed to get model: %v", err)
		}

		if model == "" {
			model, err = os.Hostname()
			if err != nil {
				model = internal.DefaultModel
			}
		}

		jwt, err := cmd.Flags().GetString("jwt")
		if err != nil {
			log.Fatalf("Failed to get jwt: %v", err)
		}

		if jwt != "" {
			log.Printf("Registering with model %s using jwt authentication", model)
		} else {
			log.Printf("Registering with model %s", model)
		}

		privKey, pubKey, err := internal.GenerateEcKeyPair()
		if err != nil {
			log.Fatalf("Failed to generate key pair: %v", err)
		}

		accountData, err := api.Register(pubKey, deviceName, model, jwt)
		if err != nil {
			log.Fatalf("Failed to register: %v", err)
		}

		log.Printf("Successful registration. Saving config...")

		EndpointV4, err := netip.ParseAddrPort(accountData.Config.Peers[0].Endpoint.V4)
		if err != nil {
			log.Fatalf("Failed to parse IPv4 endpoint: %v", err)
		}

		EndpointV6, err := netip.ParseAddrPort(accountData.Config.Peers[0].Endpoint.V6)
		if err != nil {
			log.Fatalf("Failed to parse IPv6 endpoint: %v", err)
		}

		config.AppConfig = config.Config{
			PrivateKey:     base64.StdEncoding.EncodeToString(privKey),
			EndpointV4:     EndpointV4.Addr().String(),
			EndpointV6:     EndpointV6.Addr().String(),
			EndpointPubKey: accountData.Config.Peers[0].PublicKey,
			License:        accountData.Account.License,
			ID:             accountData.ID,
			AccessToken:    accountData.Token,
			IPv4:           accountData.Config.Interface.Addresses.V4,
			IPv6:           accountData.Config.Interface.Addresses.V6,
		}

		config.AppConfig.SaveConfig(configPath)

		log.Printf("Config saved to %s", configPath)
	},
}

func init() {
	registerCmd.Flags().StringP("model", "m", "", "model")
	registerCmd.Flags().StringP("name", "n", "", "device name")
	registerCmd.Flags().String("jwt", "", "team token")
	registerCmd.Flags().BoolP("accept-tos", "a", false, "accept Cloudflare TOS (not interactive setup)")
	rootCmd.AddCommand(registerCmd)
}
