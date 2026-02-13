package k2rule

import (
	"testing"
)

// resetGlobalState resets all global state for isolated testing.
func resetGlobalState() {
	globalMutex.Lock()
	globalConfig = nil
	globalManager = nil
	globalGeoIPMgr = nil
	globalPornManager = nil
	globalMatcher = nil
	globalMutex.Unlock()
	ClearTmpRules()
}

func TestSetTmpRule_Domain(t *testing.T) {
	resetGlobalState()

	SetTmpRule("google.com", TargetProxy)
	target := Match("google.com")
	if target != TargetProxy {
		t.Errorf("Match(google.com) = %v, want TargetProxy", target)
	}
}

func TestSetTmpRule_IP(t *testing.T) {
	resetGlobalState()

	SetTmpRule("8.8.8.8", TargetReject)
	target := Match("8.8.8.8")
	if target != TargetReject {
		t.Errorf("Match(8.8.8.8) = %v, want TargetReject", target)
	}
}

func TestSetTmpRule_OverrideExisting(t *testing.T) {
	resetGlobalState()

	SetTmpRule("example.com", TargetProxy)
	if target := Match("example.com"); target != TargetProxy {
		t.Fatalf("Match(example.com) = %v, want TargetProxy", target)
	}

	// Override with a different target
	SetTmpRule("example.com", TargetReject)
	if target := Match("example.com"); target != TargetReject {
		t.Errorf("Match(example.com) after override = %v, want TargetReject", target)
	}
}

func TestSetTmpRule_StorageOptimization(t *testing.T) {
	resetGlobalState()

	// Without any manager, matchStaticRules returns TargetDirect.
	// Setting TmpRule to TargetDirect should NOT store (same as static result).
	SetTmpRule("example.com", TargetDirect)

	// Verify it was not stored by checking globalTmpRules directly
	if _, ok := globalTmpRules.Load("example.com"); ok {
		t.Error("SetTmpRule should not store when target matches static rules result")
	}

	// Setting to a different target should store
	SetTmpRule("example.com", TargetProxy)
	if _, ok := globalTmpRules.Load("example.com"); !ok {
		t.Error("SetTmpRule should store when target differs from static rules result")
	}

	// Setting back to TargetDirect should delete the stored override
	SetTmpRule("example.com", TargetDirect)
	if _, ok := globalTmpRules.Load("example.com"); ok {
		t.Error("SetTmpRule should delete existing override when target matches static rules result")
	}
}

func TestClearTmpRule(t *testing.T) {
	resetGlobalState()

	SetTmpRule("google.com", TargetProxy)
	SetTmpRule("example.com", TargetReject)

	// Clear single rule
	ClearTmpRule("google.com")

	// google.com should fall back to default (TargetDirect without rules)
	if target := Match("google.com"); target != TargetDirect {
		t.Errorf("Match(google.com) after ClearTmpRule = %v, want TargetDirect", target)
	}

	// example.com should still have TmpRule
	if target := Match("example.com"); target != TargetReject {
		t.Errorf("Match(example.com) after clearing different key = %v, want TargetReject", target)
	}
}

func TestClearTmpRules(t *testing.T) {
	resetGlobalState()

	SetTmpRule("google.com", TargetProxy)
	SetTmpRule("8.8.8.8", TargetReject)
	SetTmpRule("example.com", TargetProxy)

	ClearTmpRules()

	// All should fall back to default
	for _, input := range []string{"google.com", "8.8.8.8", "example.com"} {
		if target := Match(input); target != TargetDirect {
			t.Errorf("Match(%s) after ClearTmpRules = %v, want TargetDirect", input, target)
		}
	}
}

func TestTmpRule_PriorityOverGlobal(t *testing.T) {
	resetGlobalState()

	// Set up global mode
	globalMutex.Lock()
	globalConfig = &Config{
		IsGlobal:     true,
		GlobalTarget: TargetProxy,
	}
	globalMutex.Unlock()

	// Without TmpRule, should return GlobalTarget
	if target := Match("example.com"); target != TargetProxy {
		t.Fatalf("Match(example.com) in global mode = %v, want TargetProxy", target)
	}

	// Set TmpRule to override Global
	SetTmpRule("example.com", TargetDirect)
	if target := Match("example.com"); target != TargetDirect {
		t.Errorf("Match(example.com) with TmpRule in global mode = %v, want TargetDirect", target)
	}

	// IP should also respect TmpRule over Global
	SetTmpRule("8.8.8.8", TargetReject)
	if target := Match("8.8.8.8"); target != TargetReject {
		t.Errorf("Match(8.8.8.8) with TmpRule in global mode = %v, want TargetReject", target)
	}

	// Non-TmpRule IP should still use Global
	if target := Match("1.1.1.1"); target != TargetProxy {
		t.Errorf("Match(1.1.1.1) without TmpRule in global mode = %v, want TargetProxy", target)
	}
}

func TestTmpRule_LANBypassHigherPriority(t *testing.T) {
	resetGlobalState()

	// Set TmpRule for a LAN IP — LAN bypass should still win
	SetTmpRule("192.168.1.1", TargetProxy)
	if target := Match("192.168.1.1"); target != TargetDirect {
		t.Errorf("Match(192.168.1.1) with TmpRule = %v, want TargetDirect (LAN bypass)", target)
	}

	SetTmpRule("127.0.0.1", TargetReject)
	if target := Match("127.0.0.1"); target != TargetDirect {
		t.Errorf("Match(127.0.0.1) with TmpRule = %v, want TargetDirect (LAN bypass)", target)
	}

	SetTmpRule("::1", TargetProxy)
	if target := Match("::1"); target != TargetDirect {
		t.Errorf("Match(::1) with TmpRule = %v, want TargetDirect (LAN bypass)", target)
	}
}
