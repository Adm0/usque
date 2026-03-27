package cmd

import (
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"strings"

	"github.com/Diniboy1123/usque/api"
	"github.com/Diniboy1123/usque/config"
	"github.com/Diniboy1123/usque/internal"
	"github.com/Diniboy1123/usque/models"
	"github.com/spf13/cobra"
)

var enrollCmd = &cobra.Command{
	Use:   "enroll",
	Short: "Enrolls a MASQUE private key and switches mode",
	Long: "Enrolls a MASQUE private key and switches mode. Useful for ZeroTier where IPv6 address can change." +
		" Or if you just want to deploy a new key.",
	Run: func(cmd *cobra.Command, args []string) {
		if !config.ConfigLoaded {
			cmd.Println("Config not loaded. Please register first.")
			return
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

		regenKey, err := cmd.Flags().GetBool("regen-key")
		if err != nil {
			log.Fatalf("Failed to get regen-key: %v", err)
		}

		var (
			privKeyBytes []byte
			publicKey    []byte
		)

	retry:
		log.Printf("Enrolling device key...")
		if regenKey {
			log.Printf("Regenerating key pair...")
			privKeyBytes, publicKey, err = internal.GenerateEcKeyPair()
			if err != nil {
				log.Fatalf("Failed to generate key pair: %v", err)
			}
		} else {
			privKey, err := config.AppConfig.GetEcPrivateKey()
			if err != nil {
				log.Fatalf("Failed to get private key: %v", err)
			}

			publicKey, err = x509.MarshalPKIXPublicKey(&privKey.PublicKey)
			if err != nil {
				log.Fatalf("Failed to marshal public key: %v", err)
			}

			privKeyBytes, err = x509.MarshalECPrivateKey(privKey)
			if err != nil {
				log.Fatalf("Failed to marshal private key: %v", err)
			}
		}

		accountData, err := api.EnrollKey(publicKey, deviceName, config.AppConfig.ID, config.AppConfig.AccessToken)
		if err != nil {
			if errors.As(err, &models.APIError{}) {
				if errors.Is(err, &models.APIError{Code: models.InvalidPublicKey}) {
					fmt.Print("Invalid public key detected. Regenerate key? (y/N): ")

					var response string
					if _, err := fmt.Scanln(&response); err != nil {
						log.Fatalf("Failed to read user input: %v", err)
					}

					if strings.EqualFold(response, "y") {
						regenKey = true
						goto retry
					} else {
						log.Fatalf("Enrollment aborted by user. API errors: %v", err)
					}
				} else {
					log.Fatalf("Failed to enroll key: %v", err)
				}
			} else {
				log.Fatalf("Failed to enroll key: %v", err)
			}
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
			PrivateKey:     base64.StdEncoding.EncodeToString(privKeyBytes),
			EndpointV4:     EndpointV4.Addr().String(),
			EndpointV6:     EndpointV6.Addr().String(),
			EndpointPubKey: accountData.Config.Peers[0].PublicKey,
			License:        accountData.Account.License,
			ID:             accountData.ID,
			AccessToken:    config.AppConfig.AccessToken,
			IPv4:           accountData.Config.Interface.Addresses.V4,
			IPv6:           accountData.Config.Interface.Addresses.V6,
		}

		config.AppConfig.SaveConfig(configPath)

		log.Printf("Config saved to %s", configPath)
	},
}

func init() {
	enrollCmd.Flags().StringP("name", "n", "", "Rename device a given name")
	enrollCmd.Flags().BoolP("regen-key", "r", false, "Regenerate the key pair")
	rootCmd.AddCommand(enrollCmd)
}
