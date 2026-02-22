package k2rule

import "time"

// retryForever calls fn repeatedly until it returns nil.
// Uses exponential backoff: 1s, 2s, 4s, ..., capped at 64s.
func retryForever(fn func() error) {
	backoff := time.Second
	maxBackoff := 64 * time.Second
	for {
		if err := fn(); err == nil {
			return
		}
		time.Sleep(backoff)
		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}
