package cmd

import (
	"log"
	"time"

	"github.com/Diniboy1123/usque/api"
	"github.com/Diniboy1123/usque/config"
	"github.com/spf13/cobra"
)

var accountCmd = &cobra.Command{
	Use:   "account",
	Short: "Interaction with the account",
	Long:  "This tool allows you to get account info and licence key interaction.",
}

var accountInfoCmd = &cobra.Command{
	Use:   "info",
	Short: "Print current account information",
	Long:  "Print various information about current WARP account",
	Run: func(cmd *cobra.Command, args []string) {
		if !config.ConfigLoaded {
			cmd.Println("Config not loaded. Please register first.")
			return
		}

		account, err := api.GetAccount(config.AppConfig.ID, config.AppConfig.AccessToken)
		if err != nil {
			cmd.Printf("Failed to get account: %v\n", err)
			return
		}

		cmd.Println("Account ID:                 ", account.ID)

		if len(account.AccountType) > 0 {
			cmd.Println("Type:                       ", account.AccountType)
		}

		if created, err := time.Parse(time.RFC3339Nano, account.Created); err == nil {
			cmd.Println("Created:                    ", created)
		}

		if updated, err := time.Parse(time.RFC3339Nano, account.Updated); err == nil {
			cmd.Println("Updated:                    ", updated)
		}

		if managed, err := time.Parse(time.RFC3339Nano, account.Managed); err == nil {
			cmd.Println("Managed:                    ", managed)
		}

		if len(account.Organization) > 0 {
			cmd.Println("Organization:               ", account.Organization)
		}

		cmd.Println("Role:                       ", account.Role)
		cmd.Println("Licence Key:                ", account.License)

		if account.PremiumData > 0 {
			cmd.Println("Premium Data:               ", account.PremiumData)
		}

		if account.Quota > 0 {
			cmd.Println("Quota:                      ", account.Quota)
		}

		if account.ReferralCount > 0 {
			cmd.Println("Referral Count: ", account.ReferralCount)
		}

		if account.ReferralRenewalCount > 0 {
			cmd.Println("Referral Renewal Countdown: ", account.ReferralRenewalCount)
		}
	},
}

var accountDevicesCmd = &cobra.Command{
	Use:   "devices",
	Short: "Print connected devices",
	Long:  "Print information about devices connected with current WARP account",
	Run: func(cmd *cobra.Command, args []string) {
		if !config.ConfigLoaded {
			cmd.Println("Config not loaded. Please register first.")
			return
		}

		devices, err := api.GetDevices(config.AppConfig.ID, config.AppConfig.AccessToken)
		if err != nil {
			cmd.Printf("Failed to get devices: %v\n", err)
			return
		}

		for index, account := range *devices {
			cmd.Printf("Device #%d:\n", index+1)
			cmd.Println("  ID:         ", account.ID)

			if len(account.Type) > 0 {
				cmd.Println("  Type:       ", account.Type)
			}

			if len(account.Model) > 0 {
				cmd.Println("  Model:      ", account.Model)
			}

			if len(account.Name) > 0 {
				cmd.Println("  Name:       ", account.Name)
			}

			if created, err := time.Parse(time.RFC3339Nano, account.Created); err == nil {
				cmd.Println("  Created:    ", created)
			}

			if activated, err := time.Parse(time.RFC3339Nano, account.Activated); err == nil {
				cmd.Println("  Activated:  ", activated)
			}

			cmd.Println("  Active:     ", account.Active)

			if len(account.Role) > 0 {
				cmd.Println("  Role:       ", account.Role)
			}
		}
	},
}

var accountSetCmd = &cobra.Command{
	Use:   "set [license-key]",
	Short: "Setting WARP license key",
	Long: "Bind the current device to WARP account.\n" +
		"The key has the following format: 'xxxxxxxx-xxxxxxxx-xxxxxxxx'.",
	Args:       cobra.MinimumNArgs(1),
	ArgAliases: []string{"licence-key"},
	Run: func(cmd *cobra.Command, args []string) {
		if !config.ConfigLoaded {
			cmd.Println("Config not loaded. Please register first.")
			return
		}

		if len(args) < 1 {
			cmd.Println("require license-key argument")
			return
		}

		licenceKey := args[0]

		err := api.UpdateLicenceKey(config.AppConfig.ID, config.AppConfig.AccessToken, licenceKey)
		if err != nil {
			cmd.Printf("Failed to set licence key: %v\n", err)
			return
		}

		log.Println("Licence key successfuly changed")
	},
}

var accountResetCmd = &cobra.Command{
	Use:   "reset",
	Short: "Reset WARP license key",
	Long: "Unbind the current device to WARP account.\n" +
		"This will free space to use the key on another device.",
	Run: func(cmd *cobra.Command, args []string) {
		if !config.ConfigLoaded {
			cmd.Println("Config not loaded. Please register first.")
			return
		}

		err := api.DeleteLicenceKey(config.AppConfig.ID, config.AppConfig.AccessToken)
		if err != nil {
			cmd.Printf("Failed to reset lecence key: %v\n", err)
			return
		}

		log.Println("Licence key successfuly removed")
	},
}

func init() {
	accountCmd.AddCommand(accountInfoCmd)
	accountCmd.AddCommand(accountSetCmd)
	accountCmd.AddCommand(accountResetCmd)
	accountCmd.AddCommand(accountDevicesCmd)
	rootCmd.AddCommand(accountCmd)
}
