package k2rule

import (
	"log/slog"
	"time"
)

// retryForever calls fn repeatedly until it returns nil.
// Uses exponential backoff: 1s, 2s, 4s, ..., capped at 64s.
func retryForever(component string, fn func() error) {
	backoff := time.Second
	maxBackoff := 64 * time.Second
	for {
		err := fn()
		if err == nil {
			return
		}
		slog.Warn("retrying after error", "component", component, "error", err, "backoff", backoff)
		time.Sleep(backoff)
		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}
