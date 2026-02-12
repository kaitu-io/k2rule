package k2rule

import (
	"net"
	"testing"
)

func TestMatch_AutoDetection(t *testing.T) {
	// Test that Match() correctly auto-detects domain vs IP
	tests := []struct {
		input       string
		description string
	}{
		{"google.com", "domain"},
		{"8.8.8.8", "IPv4"},
		{"2001:4860:4860::8888", "IPv6"},
		{"192.168.1.1", "IPv4 private"},
	}

	for _, tt := range tests {
		t.Run(tt.description, func(t *testing.T) {
			// Just test that it doesn't panic - we don't have rules loaded
			target := Match(tt.input)
			// Without rules loaded, should return TargetDirect
			if target != TargetDirect {
				t.Logf("Match(%s) = %s (no rules loaded)", tt.input, target)
			}
		})
	}
}

func TestMatch_WithoutGeoIP(t *testing.T) {
	// Test that Match() works without GeoIP initialized
	// This ensures backward compatibility

	// Reset global state
	globalMutex.Lock()
	globalGeoIPMgr = nil
	globalMutex.Unlock()

	target := Match("8.8.8.8")
	// Should still work, just won't do GeoIP lookup
	if target != TargetDirect {
		t.Logf("Match without GeoIP: %s", target)
	}
}

func TestMatch_WithGeoIP_Integration(t *testing.T) {
	t.Skip("Skipping integration test - requires GeoIP database download")

	// This test requires both rules and GeoIP database using new Config API
	config := &Config{
		GeoIPURL: "", // Use default
	}
	err := Init(config)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// Test IPv4 with GeoIP
	target := Match("8.8.8.8")
	t.Logf("Match(8.8.8.8) with GeoIP = %s", target)

	// Test IPv6 with GeoIP
	target = Match("2001:4860:4860::8888")
	t.Logf("Match(2001:4860:4860::8888) with GeoIP = %s", target)
}

func TestMatchDomain_Deprecated(t *testing.T) {
	// Test deprecated MatchDomain function
	target := MatchDomain("google.com")
	// Without rules, should return Direct
	if target != TargetDirect {
		t.Logf("MatchDomain(google.com) = %s", target)
	}
}

func TestMatchIP_Deprecated(t *testing.T) {
	// Test deprecated MatchIP function
	ip := net.ParseIP("8.8.8.8")
	target := MatchIP(ip)
	// Without rules, should return Direct
	if target != TargetDirect {
		t.Logf("MatchIP(8.8.8.8) = %s", target)
	}
}

func TestMatchGeoIP_Deprecated(t *testing.T) {
	// Test deprecated MatchGeoIP function
	target := MatchGeoIP("US")
	// Without rules, should return Direct
	if target != TargetDirect {
		t.Logf("MatchGeoIP(US) = %s", target)
	}
}

func TestIsPorn_WithoutPornManager(t *testing.T) {
	// Test IsPorn without porn manager initialized
	// Should fall back to heuristic

	// Reset global state
	globalMutex.Lock()
	globalPornManager = nil
	if globalMatcher != nil {
		globalMatcher.pornChecker = nil
	}
	globalMutex.Unlock()

	isPorn := IsPorn("pornhub.com")
	if !isPorn {
		t.Error("Expected pornhub.com to be detected as porn (heuristic fallback)")
	}

	isPorn = IsPorn("google.com")
	if isPorn {
		t.Error("Expected google.com to NOT be detected as porn")
	}
}

func TestIsPorn_WithPornManager(t *testing.T) {
	t.Skip("Skipping integration test - requires porn database download")

	config := &Config{
		PornURL: "", // Use default
	}
	err := Init(config)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// Test with porn manager
	isPorn := IsPorn("pornhub.com")
	if !isPorn {
		t.Error("Expected pornhub.com to be detected as porn")
	}

	isPorn = IsPorn("google.com")
	if isPorn {
		t.Error("Expected google.com to NOT be detected as porn")
	}
}

func TestInit_WithGeoIP_DefaultURL(t *testing.T) {
	t.Skip("Skipping integration test - requires GeoIP database download")

	config := &Config{
		GeoIPURL: "", // Use default
	}
	err := Init(config)
	if err != nil {
		t.Fatalf("Init with GeoIP defaults failed: %v", err)
	}

	// Verify global manager was set
	globalMutex.RLock()
	hasManager := globalGeoIPMgr != nil
	globalMutex.RUnlock()

	if !hasManager {
		t.Error("Expected global GeoIP manager to be set")
	}
}

func TestInit_WithGeoIPFile_NotFound(t *testing.T) {
	config := &Config{
		GeoIPFile: "/nonexistent/path/GeoLite2-Country.mmdb",
	}
	err := Init(config)
	if err == nil {
		t.Error("Expected error when loading non-existent file")
	}
}

// New Config-based API tests

func TestInit_ConfigBased(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
		skip    bool
	}{
		{
			name: "pure global mode (no rules)",
			config: &Config{
				IsGlobal:     true,
				GlobalTarget: TargetProxy,
			},
			wantErr: false,
			skip:    true, // Skip: requires downloading files
		},
		{
			name:    "nil config",
			config:  nil,
			wantErr: true,
			skip:    false,
		},
		{
			name: "invalid config (both RuleURL and RuleFile)",
			config: &Config{
				RuleURL:  "https://example.com/rules.k2r.gz",
				RuleFile: "./test.k2r.gz",
			},
			wantErr: true,
			skip:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.skip {
				t.Skip("Skipping test that requires file download")
			}
			err := Init(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("Init() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestMatch_LANBypass_IPv4(t *testing.T) {
	// Test that private IPv4 addresses always return DIRECT
	privateIPs := []string{
		"192.168.1.1",
		"10.0.0.1",
		"172.16.0.1",
		"127.0.0.1",
		"169.254.1.1",
	}

	for _, ip := range privateIPs {
		t.Run(ip, func(t *testing.T) {
			target := Match(ip)
			if target != TargetDirect {
				t.Errorf("Match(%s) = %v, want TargetDirect (LAN bypass)", ip, target)
			}
		})
	}
}

func TestMatch_LANBypass_IPv6(t *testing.T) {
	// Test that private IPv6 addresses always return DIRECT
	privateIPs := []string{
		"::1",
		"fe80::1",
		"fc00::1",
	}

	for _, ip := range privateIPs {
		t.Run(ip, func(t *testing.T) {
			target := Match(ip)
			if target != TargetDirect {
				t.Errorf("Match(%s) = %v, want TargetDirect (LAN bypass)", ip, target)
			}
		})
	}
}

func TestMatch_GlobalMode(t *testing.T) {
	t.Skip("Skipping test that requires file download")

	// Initialize in global mode
	config := &Config{
		IsGlobal:     true,
		GlobalTarget: TargetProxy,
	}
	err := Init(config)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// Test that non-LAN traffic goes to GlobalTarget
	publicDomain := "google.com"
	target := Match(publicDomain)
	if target != TargetProxy {
		t.Errorf("Match(%s) in global mode = %v, want TargetProxy", publicDomain, target)
	}

	// Test that LAN IPs still bypass in global mode
	lanIP := "192.168.1.1"
	target = Match(lanIP)
	if target != TargetDirect {
		t.Errorf("Match(%s) in global mode = %v, want TargetDirect (LAN bypass)", lanIP, target)
	}
}

func TestToggleGlobal(t *testing.T) {
	t.Skip("Skipping test that requires file download")

	// Initialize in rule-based mode
	config := &Config{
		IsGlobal:     false,
		GlobalTarget: TargetProxy,
	}
	err := Init(config)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// Toggle to global mode
	ToggleGlobal(true)

	// Verify config was updated
	currentConfig := GetConfig()
	if !currentConfig.IsGlobal {
		t.Error("ToggleGlobal(true) did not set IsGlobal=true")
	}

	// Toggle back to rule-based mode
	ToggleGlobal(false)

	// Verify config was updated
	currentConfig = GetConfig()
	if currentConfig.IsGlobal {
		t.Error("ToggleGlobal(false) did not set IsGlobal=false")
	}
}

func TestGetConfig(t *testing.T) {
	t.Skip("Skipping test that requires file download")

	// Initialize with specific config
	originalConfig := &Config{
		IsGlobal:     true,
		GlobalTarget: TargetReject,
		CacheDir:     "/tmp/k2rule-test",
	}
	err := Init(originalConfig)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// Get config
	retrievedConfig := GetConfig()

	// Verify values match
	if retrievedConfig.IsGlobal != true {
		t.Errorf("GetConfig().IsGlobal = %v, want true", retrievedConfig.IsGlobal)
	}
	if retrievedConfig.GlobalTarget != TargetReject {
		t.Errorf("GetConfig().GlobalTarget = %v, want TargetReject", retrievedConfig.GlobalTarget)
	}
	if retrievedConfig.CacheDir != "/tmp/k2rule-test" {
		t.Errorf("GetConfig().CacheDir = %v, want /tmp/k2rule-test", retrievedConfig.CacheDir)
	}

	// Verify it's a copy (modifying returned config doesn't affect global)
	retrievedConfig.IsGlobal = false
	currentConfig := GetConfig()
	if !currentConfig.IsGlobal {
		t.Error("GetConfig() should return a copy, but modification affected global config")
	}
}

func TestSetGlobalTarget(t *testing.T) {
	t.Skip("Skipping test that requires file download")

	// Initialize with TargetProxy
	config := &Config{
		IsGlobal:     true,
		GlobalTarget: TargetProxy,
	}
	err := Init(config)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// Change global target
	SetGlobalTarget(TargetReject)

	// Verify config was updated
	currentConfig := GetConfig()
	if currentConfig.GlobalTarget != TargetReject {
		t.Errorf("SetGlobalTarget(TargetReject) did not update config, got %v", currentConfig.GlobalTarget)
	}
}
