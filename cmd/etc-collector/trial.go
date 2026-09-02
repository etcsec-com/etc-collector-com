package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/etcsec-com/etc-collector/internal/trial"
	"github.com/spf13/cobra"

	// Import detectors to register them via init() (required by the audit engine
	// even in trial mode since we run real audits).
	_ "github.com/etcsec-com/etc-collector/internal/audit/detectors/ad"
	_ "github.com/etcsec-com/etc-collector/internal/audit/detectors/azure"
)

var (
	trialToken       string
	trialBaseURL     string
	trialIdleTimeout time.Duration
)

var trialCmd = &cobra.Command{
	Use:   "trial",
	Short: "Run a one-shot anonymous trial session",
	Long: `Run the collector in trial mode against etcsec.com/trial.

The trial mode is stateless: no config file is written, no service is installed,
and the process exits as soon as the trial session is completed (or after the
idle timeout, default 20 minutes).

Flags can also be provided via env vars: TRIAL_TOKEN, TRIAL_BASE_URL,
TRIAL_IDLE_TIMEOUT (e.g. "10m").`,
	RunE: runTrial,
}

func init() {
	rootCmd.AddCommand(trialCmd)
	trialCmd.Flags().StringVar(&trialToken, "token", "", "Trial enrollment token (tcol_...) [env: TRIAL_TOKEN]")
	trialCmd.Flags().StringVar(&trialBaseURL, "base-url", "", "Trial service base URL [env: TRIAL_BASE_URL, default https://etcsec.com/v1/trial]")
	trialCmd.Flags().DurationVar(&trialIdleTimeout, "idle-timeout", 0, "Exit after no command for this duration [env: TRIAL_IDLE_TIMEOUT, default 20m]")
}

func runTrial(cmd *cobra.Command, args []string) error {
	token := trialToken
	if token == "" {
		token = os.Getenv("TRIAL_TOKEN")
	}
	if token == "" {
		return fmt.Errorf("trial: --token or TRIAL_TOKEN is required")
	}
	if !strings.HasPrefix(token, trial.EnrollTokenPrefix) {
		return fmt.Errorf("trial: token must start with %q", trial.EnrollTokenPrefix)
	}

	baseURL := trialBaseURL
	if baseURL == "" {
		baseURL = os.Getenv("TRIAL_BASE_URL")
	}
	if baseURL == "" {
		baseURL = trial.DefaultBaseURL
	}

	idle := trialIdleTimeout
	if idle == 0 {
		if s := os.Getenv("TRIAL_IDLE_TIMEOUT"); s != "" {
			if d, err := time.ParseDuration(s); err == nil {
				idle = d
			}
		}
	}

	edition := Edition
	if edition == "" {
		edition = "community"
	}

	code := trial.Run(context.Background(), trial.Options{
		Token:       token,
		BaseURL:     baseURL,
		IdleTimeout: idle,
		Version:     Version,
		Edition:     edition,
	})
	if code != 0 {
		os.Exit(code)
	}
	return nil
}
