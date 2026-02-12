package k2rule

import (
	"net"
	"testing"
)

func TestGeoIPManager_Init(t *testing.T) {
	// Test basic initialization
	manager := NewGeoIPManager("", "")
	if manager == nil {
		t.Fatal("NewGeoIPManager returned nil")
	}

	if manager.url != DefaultGeoIPURL {
		t.Errorf("Expected default URL %s, got %s", DefaultGeoIPURL, manager.url)
	}
}

func TestGeoIPManager_LookupCountry_AfterInit(t *testing.T) {
	t.Skip("Skipping integration test - requires internet connection and large download")

	// This test requires downloading the actual GeoIP database
	manager := NewGeoIPManager("", "")
	err := manager.Init()
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer manager.Stop()

	// Test IPv4 lookup
	ipv4 := net.ParseIP("8.8.8.8") // Google DNS, should be US
	country, err := manager.LookupCountry(ipv4)
	if err != nil {
		t.Errorf("IPv4 lookup failed: %v", err)
	}
	if country == "" {
		t.Error("IPv4 lookup returned empty country")
	}
	t.Logf("IPv4 8.8.8.8 → %s", country)

	// Test IPv6 lookup
	ipv6 := net.ParseIP("2001:4860:4860::8888") // Google DNS IPv6, should be US
	country, err = manager.LookupCountry(ipv6)
	if err != nil {
		t.Errorf("IPv6 lookup failed: %v", err)
	}
	if country == "" {
		t.Error("IPv6 lookup returned empty country")
	}
	t.Logf("IPv6 2001:4860:4860::8888 → %s", country)
}

func TestGeoIPManager_LookupCountry_NotInitialized(t *testing.T) {
	manager := NewGeoIPManager("", "")
	// Don't call Init()

	ip := net.ParseIP("8.8.8.8")
	_, err := manager.LookupCountry(ip)
	if err == nil {
		t.Error("Expected error when looking up without initialization")
	}
}

func TestNewGeoIPManager_CustomURL(t *testing.T) {
	customURL := "https://example.com/custom.mmdb.gz"
	manager := NewGeoIPManager(customURL, "")

	if manager.url != customURL {
		t.Errorf("Expected custom URL %s, got %s", customURL, manager.url)
	}
}

func TestNewGeoIPManager_CustomCacheDir(t *testing.T) {
	customDir := "/tmp/test-cache"
	manager := NewGeoIPManager("", customDir)

	if manager.cacheDir != customDir {
		t.Errorf("Expected custom cache dir %s, got %s", customDir, manager.cacheDir)
	}
}
