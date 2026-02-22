package main

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/kaitu-io/k2rule/internal/clash"
	"github.com/kaitu-io/k2rule/internal/porn"
	"github.com/kaitu-io/k2rule/internal/slice"
)

// TestGenerateAllFromClashYAML tests the generate-all logic by using mock provider rules
// instead of HTTP downloads. It reads a YAML config, pre-sets provider rules, converts,
// gzips, and verifies the output is valid K2RULEV2.
func TestGenerateAllFromClashYAML(t *testing.T) {
	// Simple test YAML with two rule-providers
	yamlContent := `
rules:
  - RULE-SET,proxy-domains,PROXY
  - RULE-SET,direct-domains,DIRECT
  - MATCH,DIRECT
rule-providers:
  proxy-domains:
    type: http
    behavior: domain
    url: "https://example.com/proxy.txt"
  direct-domains:
    type: http
    behavior: domain
    url: "https://example.com/direct.txt"
`

	c := clash.NewSliceConverter()
	c.SetProviderRules("proxy-domains", []string{"google.com", "youtube.com", "github.com"})
	c.SetProviderRules("direct-domains", []string{"baidu.com", "qq.com", "weibo.com"})

	data, err := c.Convert(yamlContent)
	if err != nil {
		t.Fatalf("Convert failed: %v", err)
	}

	if len(data) < 8 {
		t.Fatalf("Output too short: %d bytes", len(data))
	}

	// Verify magic bytes directly (uncompressed)
	if string(data[:8]) != "K2RULEV2" {
		t.Errorf("Expected magic K2RULEV2, got %q", string(data[:8]))
	}

	// Gzip and verify decompression works
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "test.k2r.gz")

	if err := writeGzip(data, outputPath); err != nil {
		t.Fatalf("writeGzip failed: %v", err)
	}

	// Verify the file can be decompressed and has correct magic
	compressed, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}

	decompressed, err := decompressGzipBytes(compressed)
	if err != nil {
		t.Fatalf("decompressGzipBytes failed: %v", err)
	}

	if string(decompressed[:8]) != "K2RULEV2" {
		t.Errorf("Expected magic K2RULEV2 after decompression, got %q", string(decompressed[:8]))
	}
}

// TestGeneratePornDomains tests the generate-porn logic with a mock blocklist.
// It builds a K2RULEV2 with target=Reject and verifies the output.
func TestGeneratePornDomains(t *testing.T) {
	// Mock blocklist content
	blocklist := "pornsite1.com\npornsite2.net\n# comment\n\nnormalsite.com\n"

	// Parse domains from blocklist
	domains := parseBlocklist(blocklist)

	if len(domains) == 0 {
		t.Fatal("No domains parsed from blocklist")
	}

	// Filter heuristic-detected domains
	filtered := filterHeuristicDomains(domains)

	// Build K2RULEV2 with target=Reject (2)
	w := slice.NewSliceWriter(0) // fallback=Direct
	if err := w.AddDomainSlice(filtered, 2); err != nil {
		t.Fatalf("AddDomainSlice failed: %v", err)
	}

	data, err := w.Build()
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	if len(data) < 8 {
		t.Fatalf("Output too short: %d bytes", len(data))
	}

	// Verify magic bytes
	if string(data[:8]) != "K2RULEV2" {
		t.Errorf("Expected magic K2RULEV2, got %q", string(data[:8]))
	}

	// Verify fallback target is 0 (Direct)
	fallback := data[16] // fallback_target offset
	if fallback != 0 {
		t.Errorf("Expected fallback=0 (Direct), got %d", fallback)
	}

	// Gzip and verify
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "porn_domains.k2r.gz")

	if err := writeGzip(data, outputPath); err != nil {
		t.Fatalf("writeGzip failed: %v", err)
	}

	compressed, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}

	// Verify output is valid gzip
	decompressed, err := decompressGzipBytes(compressed)
	if err != nil {
		t.Fatalf("Output is not valid gzip: %v", err)
	}

	// Verify decompressed data has magic "K2RULEV2"
	if string(decompressed[:8]) != "K2RULEV2" {
		t.Errorf("Decompressed data does not start with K2RULEV2, got %q", string(decompressed[:8]))
	}
}

// TestGeneratedFileSizeReasonable verifies that a K2RULEV2 file with many domains
// compresses to a reasonable size.
func TestGeneratedFileSizeReasonable(t *testing.T) {
	// Generate ~500 test domains
	domains := make([]string, 500)
	for i := 0; i < 500; i++ {
		domains[i] = fmt.Sprintf("domain%05d.example.com", i)
	}

	w := slice.NewSliceWriter(0)
	if err := w.AddDomainSlice(domains, 2); err != nil {
		t.Fatalf("AddDomainSlice failed: %v", err)
	}

	data, err := w.Build()
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	// Gzip the data
	var buf bytes.Buffer
	gz, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		t.Fatalf("gzip.NewWriterLevel failed: %v", err)
	}
	if _, err := gz.Write(data); err != nil {
		t.Fatalf("gz.Write failed: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gz.Close failed: %v", err)
	}

	compressedSize := buf.Len()

	// 500 domains should be well under 10MB when compressed
	const maxSize = 10 * 1024 * 1024 // 10MB
	if compressedSize > maxSize {
		t.Errorf("Compressed size %d bytes exceeds limit of %d bytes", compressedSize, maxSize)
	}

	// Should be at least a few hundred bytes (header + data)
	if compressedSize < 100 {
		t.Errorf("Compressed size %d bytes is suspiciously small", compressedSize)
	}

	t.Logf("500 domains compressed to %d bytes", compressedSize)
}

// TestGzipOutputDecompressable writes a .k2r.gz file and verifies it decompresses to valid K2RULEV2.
func TestGzipOutputDecompressable(t *testing.T) {
	w := slice.NewSliceWriter(1) // fallback=Proxy
	if err := w.AddDomainSlice([]string{"test.com", "example.com"}, 1); err != nil {
		t.Fatalf("AddDomainSlice failed: %v", err)
	}

	data, err := w.Build()
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "test.k2r.gz")

	if err := writeGzip(data, outputPath); err != nil {
		t.Fatalf("writeGzip failed: %v", err)
	}

	// Read the file back and decompress
	compressed, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}

	// Verify gzip magic bytes (0x1f 0x8b)
	if len(compressed) < 2 || compressed[0] != 0x1f || compressed[1] != 0x8b {
		t.Errorf("File does not start with gzip magic bytes")
	}

	decompressed, err := decompressGzipBytes(compressed)
	if err != nil {
		t.Fatalf("Decompression failed: %v", err)
	}

	// Verify K2RULEV2 magic
	if len(decompressed) < 8 {
		t.Fatalf("Decompressed data too short: %d bytes", len(decompressed))
	}
	if string(decompressed[:8]) != "K2RULEV2" {
		t.Errorf("Expected K2RULEV2, got %q", string(decompressed[:8]))
	}

	// Verify fallback target is 1 (Proxy)
	fallback := decompressed[16]
	if fallback != 1 {
		t.Errorf("Expected fallback=1 (Proxy), got %d", fallback)
	}
}

// TestPornHeuristicFiltering verifies that heuristic-detectable domains are excluded
// from the output, while non-detectable domains remain.
func TestPornHeuristicFiltering(t *testing.T) {
	// Mix of heuristic-detectable and non-detectable domains
	allDomains := []string{
		"pornhub.com",         // heuristic-detectable (contains "porn")
		"xvideos.com",         // heuristic-detectable (contains "xvideo")
		"normalsite123.com",   // not detectable
		"secretadultsite.net", // not detectable by simple keyword (no porn keyword)
		"freeporn.com",        // heuristic-detectable (contains "porn")
		"businesssite.org",    // not detectable
	}

	filtered := filterHeuristicDomains(allDomains)

	// Check that porn domains are filtered out
	for _, domain := range filtered {
		if porn.IsPornHeuristic(domain) {
			t.Errorf("Domain %q should have been filtered by heuristic but was not", domain)
		}
	}

	// Check that non-porn domains are kept
	expectedKept := []string{"normalsite123.com", "secretadultsite.net", "businesssite.org"}
	keptMap := make(map[string]bool)
	for _, d := range filtered {
		keptMap[d] = true
	}

	for _, expected := range expectedKept {
		if !keptMap[expected] {
			t.Errorf("Domain %q should have been kept but was filtered", expected)
		}
	}

	// Verify at least some domains were filtered
	if len(filtered) >= len(allDomains) {
		t.Errorf("Expected some domains to be filtered, but got %d of %d", len(filtered), len(allDomains))
	}

	t.Logf("Filtered %d of %d domains using heuristic", len(allDomains)-len(filtered), len(allDomains))
}

// TestMockHTTPServer tests downloading from a mock HTTP server (integration-style test).
func TestMockHTTPServer(t *testing.T) {
	// Create a mock HTTP server serving meta.json and blocklist
	meta := map[string]interface{}{
		"blocklist": map[string]interface{}{
			"name":    "blocklist.txt",
			"updated": "2024-01-01",
			"lines":   3,
		},
	}
	metaJSON, _ := json.Marshal(meta)

	blocklist := "pornsite1.com\npornsite2.net\nnonpornsite.com\n"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/meta.json":
			w.Header().Set("Content-Type", "application/json")
			w.Write(metaJSON)
		case "/blocklist.txt":
			w.Header().Set("Content-Type", "text/plain")
			w.Write([]byte(blocklist))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	// Test downloading meta.json
	content, err := downloadURL(server.URL + "/meta.json")
	if err != nil {
		t.Fatalf("downloadURL failed: %v", err)
	}
	if content == "" {
		t.Fatal("Downloaded content is empty")
	}

	// Verify JSON parseable
	var metaResult map[string]interface{}
	if err := json.Unmarshal([]byte(content), &metaResult); err != nil {
		t.Fatalf("Failed to parse meta.json: %v", err)
	}

	// Test downloading blocklist
	blocklistContent, err := downloadURL(server.URL + "/blocklist.txt")
	if err != nil {
		t.Fatalf("downloadURL for blocklist failed: %v", err)
	}

	domains := parseBlocklist(blocklistContent)
	if len(domains) == 0 {
		t.Fatal("No domains parsed from mock blocklist")
	}
	t.Logf("Downloaded %d domains from mock server", len(domains))
}

// TestSliceWriterEmptyBuild verifies the SliceWriter builds a valid empty K2RULEV2.
func TestSliceWriterEmptyBuild(t *testing.T) {
	w := slice.NewSliceWriter(0)
	data, err := w.Build()
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	if len(data) < 64 {
		t.Fatalf("Expected at least 64 bytes (header), got %d", len(data))
	}

	if string(data[:8]) != "K2RULEV2" {
		t.Errorf("Expected K2RULEV2 magic, got %q", string(data[:8]))
	}

	// slice_count should be 0
	sliceCount := uint32(data[12]) | uint32(data[13])<<8 | uint32(data[14])<<16 | uint32(data[15])<<24
	if sliceCount != 0 {
		t.Errorf("Expected 0 slices, got %d", sliceCount)
	}
}

// TestSliceConverterBasic tests basic SliceConverter functionality.
func TestSliceConverterBasic(t *testing.T) {
	yaml := `
rules:
  - DOMAIN,google.com,PROXY
  - MATCH,DIRECT
`
	c := clash.NewSliceConverter()
	data, err := c.Convert(yaml)
	if err != nil {
		t.Fatalf("Convert failed: %v", err)
	}

	if len(data) < 8 {
		t.Fatalf("Output too short")
	}

	if string(data[:8]) != "K2RULEV2" {
		t.Errorf("Expected K2RULEV2, got %q", string(data[:8]))
	}
}

// TestSliceConverterWithProviders tests SliceConverter with pre-set provider rules.
func TestSliceConverterWithProviders(t *testing.T) {
	yaml := `
rules:
  - RULE-SET,my-provider,PROXY
  - MATCH,DIRECT
rule-providers:
  my-provider:
    type: http
    behavior: domain
    url: "https://example.com/rules.txt"
`
	c := clash.NewSliceConverter()
	c.SetProviderRules("my-provider", []string{"google.com", "youtube.com"})

	data, err := c.Convert(yaml)
	if err != nil {
		t.Fatalf("Convert failed: %v", err)
	}

	if len(data) < 8 {
		t.Fatalf("Output too short: %d bytes", len(data))
	}

	if string(data[:8]) != "K2RULEV2" {
		t.Errorf("Expected K2RULEV2, got %q", string(data[:8]))
	}

	// slice_count should be >= 1
	sliceCount := uint32(data[12]) | uint32(data[13])<<8 | uint32(data[14])<<16 | uint32(data[15])<<24
	if sliceCount < 1 {
		t.Errorf("Expected at least 1 slice, got %d", sliceCount)
	}
}

// TestLoadProvider tests loading provider rules from YAML content.
func TestLoadProvider(t *testing.T) {
	providerYAML := `payload:
  - google.com
  - youtube.com
  - github.com
`
	c := clash.NewSliceConverter()
	if err := c.LoadProvider("test-provider", providerYAML); err != nil {
		t.Fatalf("LoadProvider failed: %v", err)
	}

	configYAML := `
rules:
  - RULE-SET,test-provider,PROXY
  - MATCH,DIRECT
rule-providers:
  test-provider:
    type: http
    behavior: domain
    url: "https://example.com/rules.txt"
`
	data, err := c.Convert(configYAML)
	if err != nil {
		t.Fatalf("Convert failed: %v", err)
	}

	if len(data) < 8 {
		t.Fatalf("Output too short: %d bytes", len(data))
	}

	if string(data[:8]) != "K2RULEV2" {
		t.Errorf("Expected K2RULEV2, got %q", string(data[:8]))
	}
}

// Helper: decompressGzipBytes decompresses gzip bytes and returns raw bytes.
func decompressGzipBytes(data []byte) ([]byte, error) {
	gr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("gzip.NewReader: %w", err)
	}
	defer gr.Close()
	return io.ReadAll(gr)
}
