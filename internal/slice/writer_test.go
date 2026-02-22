package slice

import (
	"encoding/binary"
	"strings"
	"testing"
)

// TestSliceWriterEmpty verifies an empty writer produces a valid 64-byte header-only file.
func TestSliceWriterEmpty(t *testing.T) {
	w := NewSliceWriter(0)
	data, err := w.Build()
	if err != nil {
		t.Fatalf("Build() returned error: %v", err)
	}

	if len(data) != HeaderSize {
		t.Fatalf("expected %d bytes, got %d", HeaderSize, len(data))
	}

	magic := string(data[0:8])
	if magic != "K2RULEV3" {
		t.Errorf("expected magic %q, got %q", "K2RULEV3", magic)
	}

	version := binary.LittleEndian.Uint32(data[8:12])
	if version != 1 {
		t.Errorf("expected version 1, got %d", version)
	}

	sliceCount := binary.LittleEndian.Uint32(data[12:16])
	if sliceCount != 0 {
		t.Errorf("expected slice_count 0, got %d", sliceCount)
	}
}

// TestSliceWriterFallbackTarget verifies the fallback target is stored correctly in the header.
func TestSliceWriterFallbackTarget(t *testing.T) {
	tests := []struct {
		name           string
		fallbackTarget uint8
	}{
		{"zero", 0},
		{"one", 1},
		{"max", 255},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := NewSliceWriter(tt.fallbackTarget)
			data, err := w.Build()
			if err != nil {
				t.Fatalf("Build() error: %v", err)
			}

			// FallbackTarget is at byte offset 16 (after Magic[8] + Version[4] + SliceCount[4])
			got := data[16]
			if got != tt.fallbackTarget {
				t.Errorf("FallbackTarget: expected %d, got %d", tt.fallbackTarget, got)
			}
		})
	}
}

// TestSliceWriterSingleDomain verifies a single domain slice has the correct binary layout.
func TestSliceWriterSingleDomain(t *testing.T) {
	w := NewSliceWriter(0)
	err := w.AddDomainSlice([]string{"google.com"}, 1)
	if err != nil {
		t.Fatalf("AddDomainSlice() error: %v", err)
	}

	data, err := w.Build()
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}

	// Should be: header(64) + slice_index(1*16) + domain_slice_data
	if len(data) < HeaderSize+EntrySize {
		t.Fatalf("data too short: %d bytes", len(data))
	}

	// Verify slice count = 1
	sliceCount := binary.LittleEndian.Uint32(data[12:16])
	if sliceCount != 1 {
		t.Errorf("expected slice_count 1, got %d", sliceCount)
	}

	// Parse the slice entry
	entry, err := ParseEntry(data[HeaderSize:])
	if err != nil {
		t.Fatalf("ParseEntry error: %v", err)
	}

	if entry.GetType() != SliceTypeSortedDomain {
		t.Errorf("expected SliceTypeSortedDomain, got %v", entry.GetType())
	}
	if entry.Target != 1 {
		t.Errorf("expected target 1, got %d", entry.Target)
	}
	if entry.Count != 1 {
		t.Errorf("expected count 1, got %d", entry.Count)
	}

	// Parse slice data:
	// count(4) + offsets[0](4) + sentinel(4) + strings
	sliceDataStart := int(entry.Offset)
	sliceData := data[sliceDataStart:]

	count := binary.LittleEndian.Uint32(sliceData[0:4])
	if count != 1 {
		t.Errorf("domain slice count: expected 1, got %d", count)
	}

	// offsets[0] should be 0 (first string at position 0 in strings area)
	offset0 := binary.LittleEndian.Uint32(sliceData[4:8])
	if offset0 != 0 {
		t.Errorf("offsets[0]: expected 0, got %d", offset0)
	}

	// sentinel = total strings length
	// "google.com" → ".google.com" → reversed "moc.elgoog."  (11 bytes)
	sentinel := binary.LittleEndian.Uint32(sliceData[8:12])
	expectedStr := "moc.elgoog."
	if sentinel != uint32(len(expectedStr)) {
		t.Errorf("sentinel: expected %d, got %d", len(expectedStr), sentinel)
	}

	// strings area starts at offset 12
	strArea := sliceData[12:]
	got := string(strArea[:len(expectedStr)])
	if got != expectedStr {
		t.Errorf("strings area: expected %q, got %q", expectedStr, got)
	}
}

// TestSliceWriterMultipleDomains verifies multiple domains are sorted and deduped correctly.
func TestSliceWriterMultipleDomains(t *testing.T) {
	w := NewSliceWriter(0)
	// Include duplicate and mixed case
	domains := []string{"example.com", "apple.com", "google.com", "APPLE.COM"}
	err := w.AddDomainSlice(domains, 2)
	if err != nil {
		t.Fatalf("AddDomainSlice() error: %v", err)
	}

	data, err := w.Build()
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}

	entry, err := ParseEntry(data[HeaderSize:])
	if err != nil {
		t.Fatalf("ParseEntry error: %v", err)
	}

	// Should be 3 unique domains after dedup (apple.com, example.com, google.com)
	if entry.Count != 3 {
		t.Errorf("expected count 3 (deduped), got %d", entry.Count)
	}

	sliceData := data[int(entry.Offset):]
	count := binary.LittleEndian.Uint32(sliceData[0:4])
	if count != 3 {
		t.Errorf("domain count: expected 3, got %d", count)
	}

	// Normalized reversed domains:
	// "apple.com"   → ".apple.com"   → "moc.elppa."
	// "example.com" → ".example.com" → "moc.elpmaxe."
	// "google.com"  → ".google.com"  → "moc.elgoog."
	// Sorted lexicographically (Go sort.Strings order):
	// "moc.elgoog." < "moc.elpmaxe." < "moc.elppa."
	expected := []string{"moc.elgoog.", "moc.elpmaxe.", "moc.elppa."}

	// Read offsets (count + 1 values for sentinel)
	offsets := make([]uint32, count+1)
	for i := uint32(0); i <= count; i++ {
		offsets[i] = binary.LittleEndian.Uint32(sliceData[4+i*4 : 4+i*4+4])
	}

	stringsAreaStart := 4 + (count+1)*4
	strArea := sliceData[stringsAreaStart:]

	for i, exp := range expected {
		start := offsets[i]
		end := offsets[i+1]
		got := string(strArea[start:end])
		if got != exp {
			t.Errorf("domain[%d]: expected %q, got %q", i, exp, got)
		}
	}
}

// TestSliceWriterCidrV4 verifies CIDR v4 slices have the correct binary layout.
func TestSliceWriterCidrV4(t *testing.T) {
	w := NewSliceWriter(0)
	cidrs := []CidrV4Entry{
		{Network: 0xC0A80000, PrefixLen: 16}, // 192.168.0.0/16
		{Network: 0x0A000000, PrefixLen: 8},  // 10.0.0.0/8
	}
	err := w.AddCidrV4Slice(cidrs, 3)
	if err != nil {
		t.Fatalf("AddCidrV4Slice() error: %v", err)
	}

	data, err := w.Build()
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}

	entry, err := ParseEntry(data[HeaderSize:])
	if err != nil {
		t.Fatalf("ParseEntry error: %v", err)
	}

	if entry.GetType() != SliceTypeCidrV4 {
		t.Errorf("expected SliceTypeCidrV4, got %v", entry.GetType())
	}
	if entry.Count != 2 {
		t.Errorf("expected count 2, got %d", entry.Count)
	}
	if entry.Size != 16 {
		t.Errorf("expected size 16 (2 * 8 bytes), got %d", entry.Size)
	}

	sliceData := data[int(entry.Offset):]

	// First entry: 192.168.0.0/16
	// Network BE: C0 A8 00 00, prefix_len: 16, padding: 00 00 00
	if sliceData[0] != 0xC0 || sliceData[1] != 0xA8 || sliceData[2] != 0x00 || sliceData[3] != 0x00 {
		t.Errorf("first entry network: expected C0 A8 00 00, got %02X %02X %02X %02X",
			sliceData[0], sliceData[1], sliceData[2], sliceData[3])
	}
	if sliceData[4] != 16 {
		t.Errorf("first entry prefix_len: expected 16, got %d", sliceData[4])
	}
	// Padding bytes
	if sliceData[5] != 0 || sliceData[6] != 0 || sliceData[7] != 0 {
		t.Errorf("first entry padding: expected 0 0 0, got %d %d %d", sliceData[5], sliceData[6], sliceData[7])
	}

	// Second entry: 10.0.0.0/8
	if sliceData[8] != 0x0A || sliceData[9] != 0x00 || sliceData[10] != 0x00 || sliceData[11] != 0x00 {
		t.Errorf("second entry network: expected 0A 00 00 00, got %02X %02X %02X %02X",
			sliceData[8], sliceData[9], sliceData[10], sliceData[11])
	}
	if sliceData[12] != 8 {
		t.Errorf("second entry prefix_len: expected 8, got %d", sliceData[12])
	}
}

// TestSliceWriterCidrV6 verifies CIDR v6 slices have the correct binary layout.
func TestSliceWriterCidrV6(t *testing.T) {
	w := NewSliceWriter(0)
	var network [16]byte
	network[0] = 0x20
	network[1] = 0x01
	network[2] = 0x0d
	network[3] = 0xb8
	cidrs := []CidrV6Entry{
		{Network: network, PrefixLen: 32}, // 2001:db8::/32
	}
	err := w.AddCidrV6Slice(cidrs, 4)
	if err != nil {
		t.Fatalf("AddCidrV6Slice() error: %v", err)
	}

	data, err := w.Build()
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}

	entry, err := ParseEntry(data[HeaderSize:])
	if err != nil {
		t.Fatalf("ParseEntry error: %v", err)
	}

	if entry.GetType() != SliceTypeCidrV6 {
		t.Errorf("expected SliceTypeCidrV6, got %v", entry.GetType())
	}
	if entry.Count != 1 {
		t.Errorf("expected count 1, got %d", entry.Count)
	}
	if entry.Size != 24 {
		t.Errorf("expected size 24 (1 * 24 bytes), got %d", entry.Size)
	}

	sliceData := data[int(entry.Offset):]

	// Network bytes
	for i := 0; i < 16; i++ {
		if sliceData[i] != network[i] {
			t.Errorf("network byte[%d]: expected %02X, got %02X", i, network[i], sliceData[i])
		}
	}

	// prefix_len at byte 16
	if sliceData[16] != 32 {
		t.Errorf("prefix_len: expected 32, got %d", sliceData[16])
	}

	// Padding 7 bytes (17..23)
	for i := 17; i < 24; i++ {
		if sliceData[i] != 0 {
			t.Errorf("padding byte[%d]: expected 0, got %d", i, sliceData[i])
		}
	}
}

// TestSliceWriterGeoIP verifies GeoIP slices have the correct binary layout.
func TestSliceWriterGeoIP(t *testing.T) {
	w := NewSliceWriter(0)
	countries := []string{"US", "CN", "JP"}
	err := w.AddGeoIPSlice(countries, 5)
	if err != nil {
		t.Fatalf("AddGeoIPSlice() error: %v", err)
	}

	data, err := w.Build()
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}

	entry, err := ParseEntry(data[HeaderSize:])
	if err != nil {
		t.Fatalf("ParseEntry error: %v", err)
	}

	if entry.GetType() != SliceTypeGeoIP {
		t.Errorf("expected SliceTypeGeoIP, got %v", entry.GetType())
	}
	if entry.Count != 3 {
		t.Errorf("expected count 3, got %d", entry.Count)
	}
	if entry.Size != 12 {
		t.Errorf("expected size 12 (3 * 4 bytes), got %d", entry.Size)
	}

	sliceData := data[int(entry.Offset):]

	expected := []string{"US", "CN", "JP"}
	for i, code := range expected {
		offset := i * 4
		got := string(sliceData[offset : offset+2])
		if got != code {
			t.Errorf("country[%d]: expected %q, got %q", i, code, got)
		}
		// Padding bytes should be zero
		if sliceData[offset+2] != 0 || sliceData[offset+3] != 0 {
			t.Errorf("country[%d] padding: expected 0 0, got %d %d", i, sliceData[offset+2], sliceData[offset+3])
		}
	}
}

// TestSliceWriterMultipleSlices verifies multiple slices have correct offsets in the slice index.
func TestSliceWriterMultipleSlices(t *testing.T) {
	w := NewSliceWriter(0)

	err := w.AddDomainSlice([]string{"example.com"}, 1)
	if err != nil {
		t.Fatalf("AddDomainSlice() error: %v", err)
	}

	err = w.AddGeoIPSlice([]string{"US"}, 2)
	if err != nil {
		t.Fatalf("AddGeoIPSlice() error: %v", err)
	}

	cidrs := []CidrV4Entry{{Network: 0xC0A80000, PrefixLen: 16}}
	err = w.AddCidrV4Slice(cidrs, 3)
	if err != nil {
		t.Fatalf("AddCidrV4Slice() error: %v", err)
	}

	data, err := w.Build()
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}

	// slice_count = 3
	sliceCount := binary.LittleEndian.Uint32(data[12:16])
	if sliceCount != 3 {
		t.Errorf("expected slice_count 3, got %d", sliceCount)
	}

	// Minimum size: header(64) + index(3*16) + data
	minSize := HeaderSize + 3*EntrySize
	if len(data) < minSize {
		t.Fatalf("data too short: %d, need at least %d", len(data), minSize)
	}

	// Parse all 3 entries and check types
	types := []SliceType{SliceTypeSortedDomain, SliceTypeGeoIP, SliceTypeCidrV4}
	targets := []uint8{1, 2, 3}

	var prevEnd uint32
	for i := 0; i < 3; i++ {
		entryOffset := HeaderSize + i*EntrySize
		entry, err := ParseEntry(data[entryOffset:])
		if err != nil {
			t.Fatalf("ParseEntry[%d] error: %v", i, err)
		}

		if entry.GetType() != types[i] {
			t.Errorf("entry[%d] type: expected %v, got %v", i, types[i], entry.GetType())
		}
		if entry.Target != targets[i] {
			t.Errorf("entry[%d] target: expected %d, got %d", i, targets[i], entry.Target)
		}

		// Offsets must be increasing and non-overlapping
		if i > 0 && entry.Offset < prevEnd {
			t.Errorf("entry[%d] offset %d overlaps with previous end %d", i, entry.Offset, prevEnd)
		}

		// Validate offset is within bounds
		if int(entry.Offset)+int(entry.Size) > len(data) {
			t.Errorf("entry[%d] offset+size %d exceeds data length %d",
				i, int(entry.Offset)+int(entry.Size), len(data))
		}

		prevEnd = entry.Offset + entry.Size
	}
}

// TestDomainNormalization verifies domain normalization: lowercase, dot-prefix, reverse, dedup.
func TestDomainNormalization(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected []string // reversed, normalized strings in sorted order
	}{
		{
			name:     "lowercase",
			input:    []string{"GOOGLE.COM"},
			expected: []string{"moc.elgoog."},
		},
		{
			name:     "dot-prefix and reverse",
			input:    []string{"sub.example.com"},
			expected: []string{"moc.elpmaxe.bus."},
		},
		{
			name:     "dedup",
			input:    []string{"test.com", "TEST.COM", "test.com"},
			expected: []string{"moc.tset."},
		},
		{
			name:     "sorted order",
			input:    []string{"z.com", "a.com", "m.com"},
			expected: []string{"moc.a.", "moc.m.", "moc.z."},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := NewSliceWriter(0)
			err := w.AddDomainSlice(tt.input, 1)
			if err != nil {
				t.Fatalf("AddDomainSlice() error: %v", err)
			}

			data, err := w.Build()
			if err != nil {
				t.Fatalf("Build() error: %v", err)
			}

			entry, err := ParseEntry(data[HeaderSize:])
			if err != nil {
				t.Fatalf("ParseEntry error: %v", err)
			}

			expectedCount := uint32(len(tt.expected))
			if entry.Count != expectedCount {
				t.Errorf("count: expected %d, got %d", expectedCount, entry.Count)
			}

			sliceData := data[int(entry.Offset):]
			count := binary.LittleEndian.Uint32(sliceData[0:4])

			offsets := make([]uint32, count+1)
			for i := uint32(0); i <= count; i++ {
				offsets[i] = binary.LittleEndian.Uint32(sliceData[4+i*4 : 4+i*4+4])
			}

			stringsAreaStart := 4 + (count+1)*4
			strArea := sliceData[stringsAreaStart:]

			for i, exp := range tt.expected {
				start := offsets[i]
				end := offsets[i+1]
				got := string(strArea[start:end])
				if got != exp {
					t.Errorf("domain[%d]: expected %q, got %q", i, exp, got)
				}
			}
		})
	}
}

// TestSliceWriterGeoIPUppercase verifies that GeoIP country codes are stored as uppercase.
func TestSliceWriterGeoIPUppercase(t *testing.T) {
	w := NewSliceWriter(0)
	// Pass lowercase - should be stored as uppercase
	err := w.AddGeoIPSlice([]string{"us", "cn"}, 1)
	if err != nil {
		t.Fatalf("AddGeoIPSlice() error: %v", err)
	}

	data, err := w.Build()
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}

	entry, err := ParseEntry(data[HeaderSize:])
	if err != nil {
		t.Fatalf("ParseEntry error: %v", err)
	}

	sliceData := data[int(entry.Offset):]

	// Should be stored as "US"
	if sliceData[0] != 'U' || sliceData[1] != 'S' {
		t.Errorf("expected US, got %c%c", sliceData[0], sliceData[1])
	}
	// Should be stored as "CN"
	if sliceData[4] != 'C' || sliceData[5] != 'N' {
		t.Errorf("expected CN, got %c%c", sliceData[4], sliceData[5])
	}
}

// TestSliceTypeSortedDomainConstant verifies the renamed constant exists and has the correct value.
func TestSliceTypeSortedDomainConstant(t *testing.T) {
	if SliceTypeSortedDomain != 0x01 {
		t.Errorf("SliceTypeSortedDomain: expected 0x01, got 0x%02X", SliceTypeSortedDomain)
	}
	if SliceTypeSortedDomain.String() != "SortedDomain" {
		t.Errorf("SliceTypeSortedDomain.String(): expected %q, got %q", "SortedDomain", SliceTypeSortedDomain.String())
	}
}

// TestSliceWriterChecksumFieldPresent verifies the 64-byte header has a checksum area.
func TestSliceWriterChecksumFieldPresent(t *testing.T) {
	w := NewSliceWriter(0)
	data, err := w.Build()
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}

	// The header is exactly 64 bytes
	if len(data) != HeaderSize {
		t.Fatalf("expected %d bytes for empty file, got %d", HeaderSize, len(data))
	}

	// Verify we can read a checksum from offset 24 (8+4+4+1+3+8 = 28 actually)
	// Layout: Magic(8)+Version(4)+SliceCount(4)+FallbackTarget(1)+Reserved(3)+Timestamp(8)+Checksum(16)+Reserved(16)
	// Timestamp at offset 20, Checksum at offset 28
	_ = data[28:44] // just accessing checksum area without error
}

// TestSliceWriterDomainAlreadyDotPrefixed verifies domains with existing leading dots are handled.
func TestSliceWriterDomainAlreadyDotPrefixed(t *testing.T) {
	w := NewSliceWriter(0)
	// Some input may already have a dot prefix
	err := w.AddDomainSlice([]string{"example.com", ".example.com"}, 1)
	if err != nil {
		t.Fatalf("AddDomainSlice() error: %v", err)
	}

	data, err := w.Build()
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}

	entry, err := ParseEntry(data[HeaderSize:])
	if err != nil {
		t.Fatalf("ParseEntry error: %v", err)
	}

	// Both should normalize to the same thing and be deduped to 1
	if entry.Count != 1 {
		t.Errorf("expected 1 domain after dedup of dot-prefixed variant, got %d", entry.Count)
	}
}

// TestSliceWriterHeaderTimestampNonZero verifies timestamp is set in the header.
func TestSliceWriterHeaderTimestampNonZero(t *testing.T) {
	w := NewSliceWriter(0)
	data, err := w.Build()
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}

	// Timestamp is at offset 20 (Magic[8]+Version[4]+SliceCount[4]+FallbackTarget[1]+Reserved[3] = 20)
	timestamp := int64(binary.LittleEndian.Uint64(data[20:28]))
	if timestamp == 0 {
		t.Error("expected non-zero timestamp in header")
	}
}

// TestSliceWriterOffsetAfterIndex verifies slice data offsets start after the slice index.
func TestSliceWriterOffsetAfterIndex(t *testing.T) {
	w := NewSliceWriter(0)
	err := w.AddGeoIPSlice([]string{"US"}, 1)
	if err != nil {
		t.Fatalf("AddGeoIPSlice() error: %v", err)
	}

	data, err := w.Build()
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}

	entry, err := ParseEntry(data[HeaderSize:])
	if err != nil {
		t.Fatalf("ParseEntry error: %v", err)
	}

	// Offset must be at least header + 1 slice entry = 64 + 16 = 80
	minOffset := uint32(HeaderSize + EntrySize)
	if entry.Offset < minOffset {
		t.Errorf("offset %d is before end of slice index (%d)", entry.Offset, minOffset)
	}
}

// TestSliceWriterMagicIsV3 verifies the magic is K2RULEV3 (not K2RULEV2).
func TestSliceWriterMagicIsV3(t *testing.T) {
	w := NewSliceWriter(0)
	data, err := w.Build()
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}

	magic := string(data[0:8])
	if magic != "K2RULEV3" {
		t.Errorf("expected magic K2RULEV3, got %q", magic)
	}
	if strings.Contains(magic, "K2RULEV2") {
		t.Error("magic must not be K2RULEV2")
	}
}
