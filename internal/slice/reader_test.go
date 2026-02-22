package slice

import (
	"bytes"
	"compress/gzip"
	"net"
	"os"
	"testing"
)

// helper: buildData creates a K2RULEV3 binary blob from the given writer.
func buildData(t *testing.T, w *SliceWriter) []byte {
	t.Helper()
	data, err := w.Build()
	if err != nil {
		t.Fatalf("SliceWriter.Build() error: %v", err)
	}
	return data
}

// helper: newSliceReader creates a SliceReader from raw bytes, failing the test on error.
func newSliceReader(t *testing.T, data []byte) *SliceReader {
	t.Helper()
	r, err := NewSliceReaderFromBytes(data)
	if err != nil {
		t.Fatalf("NewSliceReaderFromBytes() error: %v", err)
	}
	return r
}

// helper: gzipData compresses data with gzip and returns the compressed bytes.
func gzipData(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if _, err := gw.Write(data); err != nil {
		t.Fatalf("gzip.Write error: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gzip.Close error: %v", err)
	}
	return buf.Bytes()
}

// helper: writeTempGzip writes gzip-compressed data to a temp file, returns its path.
func writeTempGzip(t *testing.T, data []byte) string {
	t.Helper()
	gz := gzipData(t, data)
	f, err := os.CreateTemp("", "k2rule-test-*.gz")
	if err != nil {
		t.Fatalf("os.CreateTemp error: %v", err)
	}
	t.Cleanup(func() {
		os.Remove(f.Name())
	})
	if _, err := f.Write(gz); err != nil {
		f.Close()
		t.Fatalf("write temp file error: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close temp file error: %v", err)
	}
	return f.Name()
}

// helper: newMmapReaderFromGzip creates a MmapReader from a gzip temp file.
func newMmapReaderFromGzip(t *testing.T, data []byte) *MmapReader {
	t.Helper()
	path := writeTempGzip(t, data)
	r, err := NewMmapReaderFromGzip(path)
	if err != nil {
		t.Fatalf("NewMmapReaderFromGzip() error: %v", err)
	}
	t.Cleanup(func() {
		r.Close()
	})
	return r
}

// TestSortedDomainBinarySearch verifies exact match: "google.com" found when
// ".google.com" is in the domain set.
func TestSortedDomainBinarySearch(t *testing.T) {
	w := NewSliceWriter(0)
	if err := w.AddDomainSlice([]string{"google.com"}, 1); err != nil {
		t.Fatalf("AddDomainSlice error: %v", err)
	}
	data := buildData(t, w)
	r := newSliceReader(t, data)

	target := r.MatchDomain("google.com")
	if target == nil {
		t.Fatal("MatchDomain(\"google.com\") returned nil, expected match with target 1")
	}
	if *target != 1 {
		t.Errorf("expected target 1, got %d", *target)
	}
}

// TestDomainSuffixMatching verifies "www.youtube.com" matches ".youtube.com" entry.
func TestDomainSuffixMatching(t *testing.T) {
	w := NewSliceWriter(0)
	if err := w.AddDomainSlice([]string{"youtube.com"}, 2); err != nil {
		t.Fatalf("AddDomainSlice error: %v", err)
	}
	data := buildData(t, w)
	r := newSliceReader(t, data)

	tests := []struct {
		domain string
		want   uint8
		match  bool
	}{
		{"www.youtube.com", 2, true},
		{"youtube.com", 2, true},
		{"sub.sub.youtube.com", 2, true},
		{"notyoutube.com", 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			got := r.MatchDomain(tt.domain)
			if tt.match {
				if got == nil {
					t.Fatalf("MatchDomain(%q) returned nil, expected target %d", tt.domain, tt.want)
				}
				if *got != tt.want {
					t.Errorf("expected target %d, got %d", tt.want, *got)
				}
			} else {
				if got != nil {
					t.Fatalf("MatchDomain(%q) returned %d, expected nil", tt.domain, *got)
				}
			}
		})
	}
}

// TestDomainOrderingPreserved verifies slice ordering: slice1 has ".cn.bing.com" target=1,
// slice2 has ".bing.com" target=2. "cn.bing.com" should match target 1 (slice1 first).
func TestDomainOrderingPreserved(t *testing.T) {
	w := NewSliceWriter(0)
	// Slice 1: more specific — direct
	if err := w.AddDomainSlice([]string{"cn.bing.com"}, 1); err != nil {
		t.Fatalf("AddDomainSlice (slice1) error: %v", err)
	}
	// Slice 2: less specific — proxy
	if err := w.AddDomainSlice([]string{"bing.com"}, 2); err != nil {
		t.Fatalf("AddDomainSlice (slice2) error: %v", err)
	}
	data := buildData(t, w)
	r := newSliceReader(t, data)

	t.Run("cn.bing.com → target 1 (slice1 wins)", func(t *testing.T) {
		got := r.MatchDomain("cn.bing.com")
		if got == nil {
			t.Fatal("MatchDomain(\"cn.bing.com\") returned nil")
		}
		if *got != 1 {
			t.Errorf("expected target 1 (slice1), got %d", *got)
		}
	})

	t.Run("bing.com → target 2 (slice2)", func(t *testing.T) {
		got := r.MatchDomain("bing.com")
		if got == nil {
			t.Fatal("MatchDomain(\"bing.com\") returned nil")
		}
		if *got != 2 {
			t.Errorf("expected target 2 (slice2), got %d", *got)
		}
	})

	t.Run("www.bing.com → target 2 (slice2, not in slice1)", func(t *testing.T) {
		got := r.MatchDomain("www.bing.com")
		if got == nil {
			t.Fatal("MatchDomain(\"www.bing.com\") returned nil")
		}
		if *got != 2 {
			t.Errorf("expected target 2 (slice2), got %d", *got)
		}
	})
}

// TestDomainCaseInsensitive verifies "Google.COM" matches "google.com" entry.
func TestDomainCaseInsensitive(t *testing.T) {
	w := NewSliceWriter(0)
	if err := w.AddDomainSlice([]string{"google.com"}, 3); err != nil {
		t.Fatalf("AddDomainSlice error: %v", err)
	}
	data := buildData(t, w)
	r := newSliceReader(t, data)

	cases := []string{"Google.COM", "GOOGLE.COM", "google.COM", "Google.com"}
	for _, domain := range cases {
		t.Run(domain, func(t *testing.T) {
			got := r.MatchDomain(domain)
			if got == nil {
				t.Fatalf("MatchDomain(%q) returned nil, expected match", domain)
			}
			if *got != 3 {
				t.Errorf("expected target 3, got %d", *got)
			}
		})
	}
}

// TestDomainNoMatch verifies unknown domain returns nil.
func TestDomainNoMatch(t *testing.T) {
	w := NewSliceWriter(0)
	if err := w.AddDomainSlice([]string{"google.com", "youtube.com"}, 1); err != nil {
		t.Fatalf("AddDomainSlice error: %v", err)
	}
	data := buildData(t, w)
	r := newSliceReader(t, data)

	notMatching := []string{
		"facebook.com",
		"example.org",
		"oogle.com",
		"com",
		"",
	}
	for _, domain := range notMatching {
		t.Run(domain, func(t *testing.T) {
			got := r.MatchDomain(domain)
			if got != nil {
				t.Fatalf("MatchDomain(%q) returned %d, expected nil", domain, *got)
			}
		})
	}
}

// TestMmapSortedDomainMatch runs the same domain tests via MmapReader.
func TestMmapSortedDomainMatch(t *testing.T) {
	w := NewSliceWriter(0)
	if err := w.AddDomainSlice([]string{"google.com", "youtube.com"}, 5); err != nil {
		t.Fatalf("AddDomainSlice error: %v", err)
	}
	data := buildData(t, w)
	r := newMmapReaderFromGzip(t, data)

	tests := []struct {
		domain string
		match  bool
	}{
		{"google.com", true},
		{"www.google.com", true},
		{"youtube.com", true},
		{"sub.youtube.com", true},
		{"GOOGLE.COM", true},
		{"facebook.com", false},
		{"notgoogle.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			got := r.MatchDomain(tt.domain)
			if tt.match {
				if got == nil {
					t.Fatalf("MmapReader.MatchDomain(%q) returned nil, expected match", tt.domain)
				}
				if *got != 5 {
					t.Errorf("expected target 5, got %d", *got)
				}
			} else {
				if got != nil {
					t.Fatalf("MmapReader.MatchDomain(%q) returned %d, expected nil", tt.domain, *got)
				}
			}
		})
	}
}

// TestMmapReaderFromGzipV3 verifies MmapReader loads and matches correctly from a gzip K2RULEV3 file.
func TestMmapReaderFromGzipV3(t *testing.T) {
	w := NewSliceWriter(9)
	if err := w.AddDomainSlice([]string{"example.com", "test.org"}, 7); err != nil {
		t.Fatalf("AddDomainSlice error: %v", err)
	}
	data := buildData(t, w)

	path := writeTempGzip(t, data)
	r, err := NewMmapReaderFromGzip(path)
	if err != nil {
		t.Fatalf("NewMmapReaderFromGzip() error: %v", err)
	}
	defer r.Close()

	if r.Fallback() != 9 {
		t.Errorf("Fallback: expected 9, got %d", r.Fallback())
	}

	if r.SliceCount() != 1 {
		t.Errorf("SliceCount: expected 1, got %d", r.SliceCount())
	}

	got := r.MatchDomain("sub.example.com")
	if got == nil {
		t.Fatal("MatchDomain(\"sub.example.com\") returned nil")
	}
	if *got != 7 {
		t.Errorf("expected target 7, got %d", *got)
	}

	notMatch := r.MatchDomain("notexample.com")
	if notMatch != nil {
		t.Fatalf("MatchDomain(\"notexample.com\") should not match, got %d", *notMatch)
	}
}

// TestCidrV4Match verifies roundtrip: write CIDRv4, read with SliceReader, 10.1.2.3 matches 10.0.0.0/8.
func TestCidrV4Match(t *testing.T) {
	// 10.0.0.0/8: network = 0x0A000000
	network := uint32(10) << 24
	w := NewSliceWriter(0)
	if err := w.AddCidrV4Slice([]CidrV4Entry{{Network: network, PrefixLen: 8}}, 4); err != nil {
		t.Fatalf("AddCidrV4Slice error: %v", err)
	}
	data := buildData(t, w)
	r := newSliceReader(t, data)

	tests := []struct {
		ip    string
		match bool
	}{
		{"10.1.2.3", true},
		{"10.0.0.1", true},
		{"10.255.255.255", true},
		{"192.168.1.1", false},
		{"11.0.0.1", false},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("failed to parse IP %q", tt.ip)
			}
			got := r.MatchIP(ip)
			if tt.match {
				if got == nil {
					t.Fatalf("MatchIP(%q) returned nil, expected match", tt.ip)
				}
				if *got != 4 {
					t.Errorf("expected target 4, got %d", *got)
				}
			} else {
				if got != nil {
					t.Fatalf("MatchIP(%q) returned %d, expected nil", tt.ip, *got)
				}
			}
		})
	}
}

// TestCidrV6Match verifies roundtrip: write CIDRv6, read, fc00::1 matches fc00::/7.
func TestCidrV6Match(t *testing.T) {
	// fc00::/7 — first byte: 0xFC, prefix 7 bits
	var network [16]byte
	network[0] = 0xFC
	w := NewSliceWriter(0)
	if err := w.AddCidrV6Slice([]CidrV6Entry{{Network: network, PrefixLen: 7}}, 6); err != nil {
		t.Fatalf("AddCidrV6Slice error: %v", err)
	}
	data := buildData(t, w)
	r := newSliceReader(t, data)

	tests := []struct {
		ip    string
		match bool
	}{
		{"fc00::1", true},
		{"fd00::1", true},   // fd also matches fc00::/7 (bit pattern 1111110x)
		{"fe00::1", false},  // 0xFE = 1111 1110 — not in fc00::/7
		{"2001:db8::1", false},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("failed to parse IP %q", tt.ip)
			}
			got := r.MatchIP(ip)
			if tt.match {
				if got == nil {
					t.Fatalf("MatchIP(%q) returned nil, expected match", tt.ip)
				}
				if *got != 6 {
					t.Errorf("expected target 6, got %d", *got)
				}
			} else {
				if got != nil {
					t.Fatalf("MatchIP(%q) returned %d, expected nil", tt.ip, *got)
				}
			}
		})
	}
}

// TestGeoIPMatch verifies roundtrip: write GeoIP "CN", read, "CN" matches but "US" doesn't.
func TestGeoIPMatch(t *testing.T) {
	w := NewSliceWriter(0)
	if err := w.AddGeoIPSlice([]string{"CN", "JP"}, 8); err != nil {
		t.Fatalf("AddGeoIPSlice error: %v", err)
	}
	data := buildData(t, w)
	r := newSliceReader(t, data)

	tests := []struct {
		country string
		match   bool
	}{
		{"CN", true},
		{"JP", true},
		{"cn", true},   // case insensitive
		{"jp", true},
		{"US", false},
		{"DE", false},
	}

	for _, tt := range tests {
		t.Run(tt.country, func(t *testing.T) {
			got := r.MatchGeoIP(tt.country)
			if tt.match {
				if got == nil {
					t.Fatalf("MatchGeoIP(%q) returned nil, expected match", tt.country)
				}
				if *got != 8 {
					t.Errorf("expected target 8, got %d", *got)
				}
			} else {
				if got != nil {
					t.Fatalf("MatchGeoIP(%q) returned %d, expected nil", tt.country, *got)
				}
			}
		})
	}
}

// TestReaderRoundtrip verifies a full roundtrip with multiple slice types.
func TestReaderRoundtrip(t *testing.T) {
	w := NewSliceWriter(0)

	// Domain slice: target 1
	if err := w.AddDomainSlice([]string{"example.com", "test.org"}, 1); err != nil {
		t.Fatalf("AddDomainSlice error: %v", err)
	}

	// CIDR v4 slice: 192.168.0.0/16, target 2
	net192 := uint32(192)<<24 | uint32(168)<<16
	if err := w.AddCidrV4Slice([]CidrV4Entry{{Network: net192, PrefixLen: 16}}, 2); err != nil {
		t.Fatalf("AddCidrV4Slice error: %v", err)
	}

	// GeoIP slice: target 3
	if err := w.AddGeoIPSlice([]string{"CN"}, 3); err != nil {
		t.Fatalf("AddGeoIPSlice error: %v", err)
	}

	data := buildData(t, w)
	r := newSliceReader(t, data)

	if r.SliceCount() != 3 {
		t.Errorf("SliceCount: expected 3, got %d", r.SliceCount())
	}

	t.Run("domain match", func(t *testing.T) {
		got := r.MatchDomain("www.example.com")
		if got == nil {
			t.Fatal("MatchDomain(\"www.example.com\") returned nil")
		}
		if *got != 1 {
			t.Errorf("expected target 1, got %d", *got)
		}
	})

	t.Run("domain no match", func(t *testing.T) {
		got := r.MatchDomain("google.com")
		if got != nil {
			t.Fatalf("MatchDomain(\"google.com\") returned %d, expected nil", *got)
		}
	})

	t.Run("cidr v4 match", func(t *testing.T) {
		ip := net.ParseIP("192.168.5.10")
		got := r.MatchIP(ip)
		if got == nil {
			t.Fatal("MatchIP(192.168.5.10) returned nil")
		}
		if *got != 2 {
			t.Errorf("expected target 2, got %d", *got)
		}
	})

	t.Run("cidr v4 no match", func(t *testing.T) {
		ip := net.ParseIP("10.0.0.1")
		got := r.MatchIP(ip)
		if got != nil {
			t.Fatalf("MatchIP(10.0.0.1) returned %d, expected nil", *got)
		}
	})

	t.Run("geoip match", func(t *testing.T) {
		got := r.MatchGeoIP("CN")
		if got == nil {
			t.Fatal("MatchGeoIP(\"CN\") returned nil")
		}
		if *got != 3 {
			t.Errorf("expected target 3, got %d", *got)
		}
	})

	t.Run("geoip no match", func(t *testing.T) {
		got := r.MatchGeoIP("US")
		if got != nil {
			t.Fatalf("MatchGeoIP(\"US\") returned %d, expected nil", *got)
		}
	})
}
