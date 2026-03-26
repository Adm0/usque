package cmd

import (
	"encoding/base64"
	"fmt"
	"log"
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

		acceptTos, err := cmd.Flags().GetBool("accept-tos")
		if err != nil {
			log.Fatalf("Failed to get accept-tos flag: %v", err)
		}

		privKey, pubKey, err := internal.GenerateEcKeyPair()
		if err != nil {
			log.Fatalf("Failed to generate key pair: %v", err)
		}

		accountData, err := api.Register(pubKey, deviceName, model, jwt, acceptTos)
		if err != nil {
			log.Fatalf("Failed to register: %v", err)
		}

		log.Printf("Successful registration. Saving config...")

		config.AppConfig = config.Config{
			PrivateKey: base64.StdEncoding.EncodeToString(privKey),
			// TODO: proper endpoint parsing in utils
			// strip :0
			EndpointV4: accountData.Config.Peers[0].Endpoint.V4[:len(accountData.Config.Peers[0].Endpoint.V4)-2],
			// strip [ from beginning and ]:0 from end
			EndpointV6:     accountData.Config.Peers[0].Endpoint.V6[1 : len(accountData.Config.Peers[0].Endpoint.V6)-3],
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
