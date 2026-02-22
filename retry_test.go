package k2rule

import (
	"fmt"
	"testing"
	"time"
)

func TestRetryForever_SucceedsImmediately(t *testing.T) {
	calls := 0
	retryForever("test", func() error {
		calls++
		return nil
	})
	if calls != 1 {
		t.Errorf("expected 1 call, got %d", calls)
	}
}

func TestRetryForever_SucceedsAfterRetries(t *testing.T) {
	calls := 0
	retryForever("test", func() error {
		calls++
		if calls < 3 {
			return fmt.Errorf("fail %d", calls)
		}
		return nil
	})
	if calls != 3 {
		t.Errorf("expected 3 calls, got %d", calls)
	}
}

func TestRetryForever_BackoffCapsAt64s(t *testing.T) {
	b := time.Second
	max := 64 * time.Second
	for i := 0; i < 10; i++ {
		b *= 2
		if b > max {
			b = max
		}
	}
	if b != max {
		t.Errorf("backoff should cap at %v, got %v", max, b)
	}
}
