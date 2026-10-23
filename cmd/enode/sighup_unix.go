//go:build unix

package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"enode/logging"
)

// watchReopen closes and reopens the log files on SIGHUP, so an external logrotate
// that moved them away gets new files at the same paths. Each reopen is one log file
// besides the server log. SIGHUP no longer ends the process.
func watchReopen(ctx context.Context, reopen ...func() error) {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGHUP)
	go func() {
		defer signal.Stop(sig)
		for {
			select {
			case <-ctx.Done():
				return
			case <-sig:
				if err := logging.Reopen(); err != nil {
					logging.Errorf("SIGHUP: log file not reopened: %v", err)
				}
				for _, r := range reopen {
					if err := r(); err != nil {
						logging.Errorf("SIGHUP: log file not reopened: %v", err)
					}
				}
				logging.Infof("SIGHUP: log files reopened")
			}
		}
	}()
}
