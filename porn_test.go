package k2rule

import (
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// testK2RGzBase64 is a pre-built K2R file with pornhub.com, xvideos.com, xnxx.com as REJECT (target=2)
// Generated from:
//   rules:
//     - DOMAIN-SUFFIX,pornhub.com,REJECT
//     - DOMAIN-SUFFIX,xvideos.com,REJECT
//     - DOMAIN-SUFFIX,xnxx.com,REJECT
//     - MATCH,DIRECT
const testK2RGzBase64 = "H4sIAAAAAAAC/42LvQ1AQBhAvyOoJLeHRq6wwVUUImEAnVqj1IsFFAYwgVou8RcibKDUWsBJ7gqdl7y86rkkCD0aEQQArxLnrhL4AVIAfF7KVYUfcDmyfl4PAzfnsHdMx8WFNDNLY6wuE9vkYIvWeWs9JxBqH5UAAAA="

// testSingleDomainK2RGzBase64 is a pre-built K2R file with just pornhub.com as REJECT (target=2)
// Generated from:
//   rules:
//     - DOMAIN-SUFFIX,pornhub.com,REJECT
//     - MATCH,DIRECT
const testSingleDomainK2RGzBase64 = "H4sIAAAAAAAC/42NsQmAMBREL7qAC7jE38FKCxG0cAN3sLN2AaexCIiKEkgTskYWSAJJkyoPjtfccS0NY9dMxAD4RFZzLMiAFUDvTGFfpoVqv/n1/lJ/DxfxoQ6e1blZlAR9S4IAAAA="

// writeTestK2RFile writes a base64-encoded K2R gzip file to the given path.
func writeTestK2RFile(t *testing.T, path, b64Data string) {
	t.Helper()

	data, err := base64.StdEncoding.DecodeString(b64Data)
	if err != nil {
		t.Fatalf("failed to decode base64 test data: %v", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatalf("failed to write test K2R file: %v", err)
	}
}

// TestPornCheckerWithSliceReader creates a K2R file with porn domains (target=Reject)
// using the pre-built test binary, loads via PornChecker, and verifies IsPorn returns true.
func TestPornCheckerWithSliceReader(t *testing.T) {
	tmpDir := t.TempDir()
	k2rPath := filepath.Join(tmpDir, "test_porn.k2r.gz")

	writeTestK2RFile(t, k2rPath, testK2RGzBase64)

	checker, err := NewPornCheckerFromFile(k2rPath)
	if err != nil {
		t.Fatalf("NewPornCheckerFromFile failed: %v", err)
	}

	// All three domains should be detected as porn via SliceReader
	pornDomains := []string{
		"pornhub.com",
		"xvideos.com",
		"xnxx.com",
	}

	for _, domain := range pornDomains {
		t.Run(domain, func(t *testing.T) {
			if !checker.IsPorn(domain) {
				t.Errorf("IsPorn(%q) = false, want true (domain is in K2R file)", domain)
			}
		})
	}

	// Non-porn domain should return false (no heuristic match, not in file)
	if checker.IsPorn("google.com") {
		t.Error("IsPorn(google.com) = true, want false")
	}
}

// TestPornCheckerHeuristicFallback verifies heuristic detection works without any file loaded.
func TestPornCheckerHeuristicFallback(t *testing.T) {
	checker := NewPornChecker()

	// Heuristic should detect porn-keyword domains
	heuristicPorn := []string{
		"xxx-site.com",
		"sexvideos.com",
		"pornhub.com",
	}

	for _, domain := range heuristicPorn {
		t.Run(domain, func(t *testing.T) {
			if !checker.IsPorn(domain) {
				t.Errorf("IsPorn(%q) = false, want true (heuristic should detect)", domain)
			}
		})
	}

	// Non-porn domains should return false
	nonPorn := []string{
		"google.com",
		"github.com",
		"stackoverflow.com",
	}

	for _, domain := range nonPorn {
		t.Run(domain, func(t *testing.T) {
			if checker.IsPorn(domain) {
				t.Errorf("IsPorn(%q) = true, want false (not porn)", domain)
			}
		})
	}
}

// TestPornCheckerSuffixMatch creates a K2R file with "pornhub.com" and verifies
// that "www.pornhub.com" also matches via suffix matching in SliceReader.
func TestPornCheckerSuffixMatch(t *testing.T) {
	tmpDir := t.TempDir()
	k2rPath := filepath.Join(tmpDir, "test_single.k2r.gz")

	writeTestK2RFile(t, k2rPath, testSingleDomainK2RGzBase64)

	checker, err := NewPornCheckerFromFile(k2rPath)
	if err != nil {
		t.Fatalf("NewPornCheckerFromFile failed: %v", err)
	}

	// Exact domain should match
	if !checker.IsPorn("pornhub.com") {
		t.Error("IsPorn(pornhub.com) = false, want true")
	}

	// Subdomain should also match via suffix matching
	if !checker.IsPorn("www.pornhub.com") {
		t.Error("IsPorn(www.pornhub.com) = false, want true (suffix match)")
	}

	// Multi-level subdomain should also match
	if !checker.IsPorn("api.www.pornhub.com") {
		t.Error("IsPorn(api.www.pornhub.com) = false, want true (suffix match)")
	}

	// Unrelated domain should not match (no heuristic, not in file)
	if checker.IsPorn("google.com") {
		t.Error("IsPorn(google.com) = true, want false")
	}
}

// TestPornRemoteManagerK2R verifies that PornRemoteManager uses .k2r.gz extension.
func TestPornRemoteManagerK2R(t *testing.T) {
	manager := NewPornRemoteManager("https://example.com/porn_domains.k2r.gz", "/tmp/test-cache")

	cachePath := manager.getCachePath()

	if !strings.HasSuffix(cachePath, ".k2r.gz") {
		t.Errorf("getCachePath() = %q, want path ending with .k2r.gz", cachePath)
	}

	if strings.HasSuffix(cachePath, ".fst.gz") {
		t.Errorf("getCachePath() = %q, must NOT end with .fst.gz", cachePath)
	}

	// Verify the hash-based filename uses k2r.gz
	hash := sha256.Sum256([]byte("https://example.com/porn_domains.k2r.gz"))
	expectedFilename := fmt.Sprintf("%x.k2r.gz", hash[:8])
	expectedPath := filepath.Join("/tmp/test-cache", expectedFilename)

	if cachePath != expectedPath {
		t.Errorf("getCachePath() = %q, want %q", cachePath, expectedPath)
	}
}

// TestPornCheckerFromFile writes a valid K2R .k2r.gz file to a temp dir,
// loads it with NewPornCheckerFromFile, and verifies matching works.
func TestPornCheckerFromFile(t *testing.T) {
	tmpDir := t.TempDir()
	k2rPath := filepath.Join(tmpDir, "porn_domains.k2r.gz")

	writeTestK2RFile(t, k2rPath, testK2RGzBase64)

	// Verify the file exists and is valid gzip
	data, err := os.ReadFile(k2rPath)
	if err != nil {
		t.Fatalf("failed to read test file: %v", err)
	}

	if len(data) < 2 || data[0] != 0x1f || data[1] != 0x8b {
		t.Fatal("test file is not valid gzip")
	}

	gr, err := gzip.NewReader(strings.NewReader(string(data)))
	if err != nil {
		t.Fatalf("failed to open gzip reader: %v", err)
	}
	gr.Close()

	// Load with NewPornCheckerFromFile
	checker, err := NewPornCheckerFromFile(k2rPath)
	if err != nil {
		t.Fatalf("NewPornCheckerFromFile(%q) failed: %v", k2rPath, err)
	}

	if checker == nil {
		t.Fatal("NewPornCheckerFromFile returned nil checker")
	}

	// Verify matching works
	if !checker.IsPorn("pornhub.com") {
		t.Error("IsPorn(pornhub.com) = false, want true")
	}

	if !checker.IsPorn("xvideos.com") {
		t.Error("IsPorn(xvideos.com) = false, want true")
	}

	if checker.IsPorn("google.com") {
		t.Error("IsPorn(google.com) = true, want false")
	}
}

// TestDefaultPornURLUsesK2R verifies that DefaultPornURL uses the .k2r.gz format.
func TestDefaultPornURLUsesK2R(t *testing.T) {
	if !strings.HasSuffix(DefaultPornURL, ".k2r.gz") {
		t.Errorf("DefaultPornURL = %q, want URL ending with .k2r.gz", DefaultPornURL)
	}

	if strings.Contains(DefaultPornURL, ".fst.gz") {
		t.Errorf("DefaultPornURL = %q, must NOT contain .fst.gz", DefaultPornURL)
	}
}
