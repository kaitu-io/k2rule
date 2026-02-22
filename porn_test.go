package k2rule

import (
	"compress/gzip"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kaitu-io/k2rule/internal/slice"
)

// buildTestPornK2R builds a K2RULEV3 binary with the given domains as REJECT (target=2).
func buildTestPornK2R(t *testing.T, domains []string) []byte {
	t.Helper()
	w := slice.NewSliceWriter(0) // fallback = Direct
	if err := w.AddDomainSlice(domains, 2); err != nil {
		t.Fatalf("AddDomainSlice failed: %v", err)
	}
	data, err := w.Build()
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}
	return data
}

// writeTestK2RGzipFile writes K2RULEV3 data as a gzip file.
func writeTestK2RGzipFile(t *testing.T, path string, k2rData []byte) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("failed to create file: %v", err)
	}
	defer f.Close()

	gw, err := gzip.NewWriterLevel(f, gzip.BestCompression)
	if err != nil {
		t.Fatalf("failed to create gzip writer: %v", err)
	}
	if _, err := gw.Write(k2rData); err != nil {
		t.Fatalf("failed to write gzip: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("failed to close gzip: %v", err)
	}
}

// TestPornCheckerWithSliceReader creates a K2R file with porn domains (target=Reject)
// using SliceWriter, loads via PornChecker, and verifies IsPorn returns true.
func TestPornCheckerWithSliceReader(t *testing.T) {
	tmpDir := t.TempDir()
	k2rPath := filepath.Join(tmpDir, "test_porn.k2r.gz")

	k2rData := buildTestPornK2R(t, []string{"pornhub.com", "xvideos.com", "xnxx.com"})
	writeTestK2RGzipFile(t, k2rPath, k2rData)

	checker, err := NewPornCheckerFromFile(k2rPath)
	if err != nil {
		t.Fatalf("NewPornCheckerFromFile failed: %v", err)
	}

	pornDomains := []string{"pornhub.com", "xvideos.com", "xnxx.com"}
	for _, domain := range pornDomains {
		t.Run(domain, func(t *testing.T) {
			if !checker.IsPorn(domain) {
				t.Errorf("IsPorn(%q) = false, want true", domain)
			}
		})
	}

	if checker.IsPorn("google.com") {
		t.Error("IsPorn(google.com) = true, want false")
	}
}

// TestPornCheckerHeuristicFallback verifies heuristic detection works without any file loaded.
func TestPornCheckerHeuristicFallback(t *testing.T) {
	checker := NewPornChecker()

	heuristicPorn := []string{"xxx-site.com", "sexvideos.com", "pornhub.com"}
	for _, domain := range heuristicPorn {
		t.Run(domain, func(t *testing.T) {
			if !checker.IsPorn(domain) {
				t.Errorf("IsPorn(%q) = false, want true (heuristic)", domain)
			}
		})
	}

	nonPorn := []string{"google.com", "github.com", "stackoverflow.com"}
	for _, domain := range nonPorn {
		t.Run(domain, func(t *testing.T) {
			if checker.IsPorn(domain) {
				t.Errorf("IsPorn(%q) = true, want false", domain)
			}
		})
	}
}

// TestPornCheckerSuffixMatch verifies subdomain matching via SliceReader.
func TestPornCheckerSuffixMatch(t *testing.T) {
	tmpDir := t.TempDir()
	k2rPath := filepath.Join(tmpDir, "test_single.k2r.gz")

	k2rData := buildTestPornK2R(t, []string{"pornhub.com"})
	writeTestK2RGzipFile(t, k2rPath, k2rData)

	checker, err := NewPornCheckerFromFile(k2rPath)
	if err != nil {
		t.Fatalf("NewPornCheckerFromFile failed: %v", err)
	}

	if !checker.IsPorn("pornhub.com") {
		t.Error("IsPorn(pornhub.com) = false, want true")
	}
	if !checker.IsPorn("www.pornhub.com") {
		t.Error("IsPorn(www.pornhub.com) = false, want true (suffix match)")
	}
	if !checker.IsPorn("api.www.pornhub.com") {
		t.Error("IsPorn(api.www.pornhub.com) = false, want true (suffix match)")
	}
	if checker.IsPorn("google.com") {
		t.Error("IsPorn(google.com) = true, want false")
	}
}

// TestPornRemoteManagerK2R verifies that PornRemoteManager uses .k2r.gz extension.
func TestPornRemoteManagerK2R(t *testing.T) {
	manager := NewPornRemoteManager("https://example.com/porn_domains.k2r.gz", "/tmp/test-cache")
	cachePath := manager.getCachePath()

	if !strings.HasSuffix(cachePath, ".k2r.gz") {
		t.Errorf("getCachePath() = %q, want .k2r.gz suffix", cachePath)
	}
	if strings.HasSuffix(cachePath, ".fst.gz") {
		t.Errorf("getCachePath() = %q, must NOT end with .fst.gz", cachePath)
	}

	hash := sha256.Sum256([]byte("https://example.com/porn_domains.k2r.gz"))
	expectedPath := filepath.Join("/tmp/test-cache", fmt.Sprintf("%x.k2r.gz", hash[:8]))
	if cachePath != expectedPath {
		t.Errorf("getCachePath() = %q, want %q", cachePath, expectedPath)
	}
}

// TestPornCheckerFromFile writes a valid K2R .k2r.gz file and loads it.
func TestPornCheckerFromFile(t *testing.T) {
	tmpDir := t.TempDir()
	k2rPath := filepath.Join(tmpDir, "porn_domains.k2r.gz")

	k2rData := buildTestPornK2R(t, []string{"pornhub.com", "xvideos.com", "xnxx.com"})
	writeTestK2RGzipFile(t, k2rPath, k2rData)

	checker, err := NewPornCheckerFromFile(k2rPath)
	if err != nil {
		t.Fatalf("NewPornCheckerFromFile(%q) failed: %v", k2rPath, err)
	}

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

// TestDefaultPornURLUsesK2R verifies that DefaultPornURL uses .k2r.gz format.
func TestDefaultPornURLUsesK2R(t *testing.T) {
	if !strings.HasSuffix(DefaultPornURL, ".k2r.gz") {
		t.Errorf("DefaultPornURL = %q, want .k2r.gz suffix", DefaultPornURL)
	}
	if strings.Contains(DefaultPornURL, ".fst.gz") {
		t.Errorf("DefaultPornURL = %q, must NOT contain .fst.gz", DefaultPornURL)
	}
}
