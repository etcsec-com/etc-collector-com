package trial

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/etcsec-com/etc-collector/internal/logger"
)

// Options configures a trial run. Only Token is required; the rest have safe defaults.
type Options struct {
	Token       string
	BaseURL     string        // default: DefaultBaseURL
	IdleTimeout time.Duration // default: DefaultIdleTimeout
	Version     string
	Edition     string
}

// Run is the entrypoint: enroll, poll, execute, exit. Returns the process exit code.
func Run(ctx context.Context, opts Options) int {
	log := logger.Global().Named("trial")

	if opts.Token == "" {
		log.Error("TRIAL_TOKEN is required")
		return 2
	}
	if opts.BaseURL == "" {
		opts.BaseURL = DefaultBaseURL
	}
	if opts.IdleTimeout <= 0 {
		opts.IdleTimeout = DefaultIdleTimeout
	}

	client, err := NewClient(opts.BaseURL)
	if err != nil {
		log.Error("Invalid trial configuration", "error", err)
		return 2
	}

	// Graceful shutdown via SIGINT/SIGTERM.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Info("Trial: received shutdown signal, exiting")
		cancel()
	}()

	// Enroll.
	hostname, _ := os.Hostname()
	enrollCtx, enrollCancel := context.WithTimeout(ctx, 30*time.Second)
	enroll, err := client.Enroll(enrollCtx, EnrollRequest{
		EnrollmentToken:  opts.Token,
		Hostname:         hostname,
		OsType:           runtime.GOOS,
		Arch:             runtime.GOARCH,
		CollectorVersion: opts.Version,
		CollectorEdition: opts.Edition,
	})
	enrollCancel()
	if err != nil {
		log.Error("Trial enrollment failed", "error", err)
		return 1
	}
	if err := client.SetAPIToken(enroll.APIToken); err != nil {
		log.Error("Trial API token invalid", "error", err)
		return 1
	}

	session := &Session{
		BaseURL:      opts.BaseURL,
		CollectorID:  enroll.CollectorID,
		APIToken:     enroll.APIToken,
		PollInterval: time.Duration(enroll.PollInterval) * time.Second,
		IdleTimeout:  opts.IdleTimeout,
		LastCommand:  time.Now(),
	}
	if session.PollInterval < 5*time.Second {
		session.PollInterval = 10 * time.Second
	}
	log.Info("Trial session started",
		"collectorId", session.CollectorID,
		"pollInterval", session.PollInterval.String(),
		"idleTimeout", session.IdleTimeout.String(),
	)

	executor := NewExecutor(log, opts.Version, opts.Edition)

	// Poll loop.
	for {
		if ctx.Err() != nil {
			log.Info("Trial: context cancelled, exiting")
			return 0
		}

		pollCtx, pollCancel := context.WithTimeout(ctx, 30*time.Second)
		res, err := client.PollCommands(pollCtx)
		pollCancel()
		if err != nil {
			log.Warn("Trial poll failed", "error", err)
			if sleepOrCancel(ctx, session.PollInterval) {
				return 0
			}
			continue
		}

		if res.Completed {
			log.Info("Trial session completed by server, exiting")
			return 0
		}

		if res.Idle {
			if time.Since(session.LastCommand) > session.IdleTimeout {
				log.Info("Trial: idle timeout reached, exiting",
					"idleFor", time.Since(session.LastCommand).String())
				return 0
			}
			if sleepOrCancel(ctx, session.PollInterval) {
				return 0
			}
			continue
		}

		if res.Command == nil {
			if sleepOrCancel(ctx, session.PollInterval) {
				return 0
			}
			continue
		}

		log.Info("Trial command received", "id", res.Command.ID, "type", res.Command.Type)
		session.LastCommand = time.Now()
		result := executor.Execute(ctx, res.Command)

		subCtx, subCancel := context.WithTimeout(ctx, 5*time.Minute)
		if err := client.SubmitResult(subCtx, res.Command.ID, result); err != nil {
			log.Error("Trial: failed to submit result", "commandId", res.Command.ID, "error", err)
		} else {
			log.Info("Trial: result submitted", "commandId", res.Command.ID, "status", result.Status)
		}
		subCancel()
	}
}

// sleepOrCancel sleeps for d or returns true if the context was cancelled.
func sleepOrCancel(ctx context.Context, d time.Duration) bool {
	select {
	case <-time.After(d):
		return false
	case <-ctx.Done():
		return true
	}
}

// String returns a short human description for log messages (reserved helper).
func (s *Session) String() string {
	return fmt.Sprintf("trial-session{%s, poll=%s}", s.CollectorID, s.PollInterval)
}
