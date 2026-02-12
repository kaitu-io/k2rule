package k2rule

import (
	"testing"
)

func TestPornRemoteManager_Init(t *testing.T) {
	// Test basic initialization
	manager := NewPornRemoteManager("", "")
	if manager == nil {
		t.Fatal("NewPornRemoteManager returned nil")
	}

	if manager.url != DefaultPornURL {
		t.Errorf("Expected default URL %s, got %s", DefaultPornURL, manager.url)
	}
}

func TestPornRemoteManager_IsPorn_NotInitialized(t *testing.T) {
	manager := NewPornRemoteManager("", "")
	// Don't call Init()

	// Should fall back to heuristic
	isPorn := manager.IsPorn("pornhub.com")
	if !isPorn {
		t.Error("Expected pornhub.com to be detected as porn (heuristic)")
	}
}

func TestInit_WithPorn_Integration(t *testing.T) {
	t.Skip("Skipping integration test - requires internet connection and download")

	// This test requires downloading the actual porn database using new Config API
	config := &Config{
		PornURL: "", // Use default
	}
	err := Init(config)
	if err != nil {
		t.Fatalf("Init with porn failed: %v", err)
	}

	// Test that IsPorn now uses FST
	isPorn := IsPorn("pornhub.com")
	if !isPorn {
		t.Error("Expected pornhub.com to be detected as porn")
	}

	isPorn = IsPorn("google.com")
	if isPorn {
		t.Error("Expected google.com to NOT be detected as porn")
	}
}

func TestInit_WithPorn_CustomURL(t *testing.T) {
	t.Skip("Skipping test - would attempt to download from custom URL")

	customURL := "https://example.com/custom_porn.fst.gz"
	config := &Config{
		PornURL: customURL,
	}
	err := Init(config)
	if err == nil {
		t.Error("Expected error with invalid custom URL")
	}
}

func TestNewPornRemoteManager_CustomCacheDir(t *testing.T) {
	customDir := "/tmp/test-porn-cache"
	manager := NewPornRemoteManager("", customDir)

	if manager.cacheDir != customDir {
		t.Errorf("Expected custom cache dir %s, got %s", customDir, manager.cacheDir)
	}
}
