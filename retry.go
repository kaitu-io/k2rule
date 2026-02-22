package k2rule

import (
	"time"
)

// retryForever calls fn repeatedly until it returns nil.
// On each failure it waits 5 seconds before retrying.
// It never returns — callers that need a blocking retry use it directly,
// while non-blocking callers wrap it in a goroutine.
func retryForever(fn func() error) {
	for {
		if err := fn(); err == nil {
			return
		}
		time.Sleep(5 * time.Second)
	}
}
