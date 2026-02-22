package k2rule

import (
	"testing"
)

func TestNewRemoteRuleManager_NoCacheDirFallback(t *testing.T) {
	manager := NewRemoteRuleManager("", "", TargetDirect)
	if manager.cacheDir != "" {
		t.Errorf("expected empty cacheDir, got %q", manager.cacheDir)
	}
}
