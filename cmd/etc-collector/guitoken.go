package main

import (
	"fmt"

	"github.com/etcsec-com/etc-collector/internal/guitoken"
	"github.com/etcsec-com/etc-collector/internal/saas"
	"github.com/spf13/cobra"
)

var guiTokenCmd = &cobra.Command{
	Use:   "gui-token",
	Short: "Manage GUI access token",
	Long: `Manage the GUI access token used to authenticate with the web interface.

The GUI token is generated at install time and shown once. Only a SHA-256
hash is stored on disk — the plaintext token is never saved.

If you lose the token, use 'gui-token reset' to generate a new one.`,
}

var guiTokenResetCmd = &cobra.Command{
	Use:   "reset",
	Short: "Generate a new GUI access token",
	Long: `Generate a new GUI access token, replacing the previous one.

The new token is displayed once and never stored. Save it securely.
A service restart is required for the new token to take effect.`,
	RunE: runGuiTokenReset,
}

func init() {
	rootCmd.AddCommand(guiTokenCmd)
	guiTokenCmd.AddCommand(guiTokenResetCmd)
}

func runGuiTokenReset(cmd *cobra.Command, args []string) error {
	// This writes the GUI token hash — a secret. No silent relative fallback.
	configDir, err := saas.DefaultConfigDir()
	if err != nil {
		return err
	}

	token, err := guitoken.Generate()
	if err != nil {
		return fmt.Errorf("generate token: %w", err)
	}

	hash := guitoken.Hash(token)
	if err := guitoken.SaveHash(configDir, hash); err != nil {
		return fmt.Errorf("save token hash: %w", err)
	}

	fmt.Println("New GUI access token generated:")
	fmt.Println()
	fmt.Printf("  Token:  %s\n", token)
	fmt.Println()
	fmt.Println("  Save this token — it will not be shown again.")
	fmt.Println("  Restart the service for the new token to take effect.")
	return nil
}
