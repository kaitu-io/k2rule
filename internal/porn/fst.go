package porn

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/kaitu-io/k2rule/internal/slice"
)

// FST constants
const (
	// FSTMagic is the magic bytes for FST porn domain file format
	FSTMagic = "PORNFST\x01"
	// FSTVersion is the current version of the file format
	FSTVersion = 1
	// FSTHeaderSize is header size: magic (8) + version (4) + timestamp (8) + domain_count (4) = 24 bytes
	FSTHeaderSize = 24
)

// FSTChecker is an FST-based porn domain checker
type FSTChecker struct {
	fst         *slice.FSTReader
	domainCount uint32
	version     uint32
}

// NewFSTCheckerFromBytes loads an FST porn checker from raw bytes
func NewFSTCheckerFromBytes(data []byte) (*FSTChecker, error) {
	if len(data) < FSTHeaderSize {
		return nil, fmt.Errorf("FST data too short: %d bytes", len(data))
	}

	// Verify magic
	magic := string(data[0:8])
	if magic != FSTMagic {
		return nil, fmt.Errorf("invalid FST magic bytes: got %q, want %q", magic, FSTMagic)
	}

	// Read header
	version := binary.LittleEndian.Uint32(data[8:12])
	// Skip timestamp at [12:20]
	domainCount := binary.LittleEndian.Uint32(data[20:24])

	// Load FST
	fstData := data[FSTHeaderSize:]
	fst, err := slice.NewFSTReader(fstData)
	if err != nil {
		return nil, fmt.Errorf("failed to load FST: %w", err)
	}

	return &FSTChecker{
		fst:         fst,
		domainCount: domainCount,
		version:     version,
	}, nil
}

// NewFSTCheckerFromGzip loads an FST porn checker from gzip-compressed bytes
func NewFSTCheckerFromGzip(gzipData []byte) (*FSTChecker, error) {
	gr, err := gzip.NewReader(bytes.NewReader(gzipData))
	if err != nil {
		return nil, fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gr.Close()

	data, err := io.ReadAll(gr)
	if err != nil {
		return nil, fmt.Errorf("failed to decompress FST data: %w", err)
	}

	return NewFSTCheckerFromBytes(data)
}

// NewFSTCheckerFromFile loads an FST porn checker from a file
// Supports both plain .fst and gzip-compressed .fst.gz files
func NewFSTCheckerFromFile(path string) (*FSTChecker, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	// Check if gzip compressed (magic bytes: 0x1f 0x8b)
	if len(data) >= 2 && data[0] == 0x1f && data[1] == 0x8b {
		return NewFSTCheckerFromGzip(data)
	}

	return NewFSTCheckerFromBytes(data)
}

// IsPorn checks if a domain is in the porn list
//
// Supports suffix matching: if .example.com is in the list,
// both example.com and www.example.com will match.
func (c *FSTChecker) IsPorn(domain string) bool {
	if domain == "" {
		return false
	}

	normalized := strings.ToLower(domain)

	// Try exact match first (reversed)
	reversed := reverseString(normalized)
	if c.fst.Contains([]byte(reversed)) {
		return true
	}

	// Try suffix match with dot prefix
	withDot := "." + normalized
	reversedWithDot := reverseString(withDot)
	if c.fst.Contains([]byte(reversedWithDot)) {
		return true
	}

	// Check all parent domains for suffix matches
	parts := strings.Split(normalized, ".")
	for i := 1; i < len(parts); i++ {
		suffix := strings.Join(parts[i:], ".")
		suffixWithDot := "." + suffix
		reversedSuffix := reverseString(suffixWithDot)
		if c.fst.Contains([]byte(reversedSuffix)) {
			return true
		}
	}

	return false
}

// DomainCount returns the number of domains in the set
func (c *FSTChecker) DomainCount() uint32 {
	return c.domainCount
}

// Version returns the file format version
func (c *FSTChecker) Version() uint32 {
	return c.version
}

// reverseString reverses a string
func reverseString(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}
