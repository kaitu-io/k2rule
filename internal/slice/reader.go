package slice

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
)

// SliceReader reads and queries K2Rule slice-based rule files
type SliceReader struct {
	data    []byte
	header  *SliceHeader
	entries []*SliceEntry
}

// NewSliceReaderFromBytes loads a SliceReader from raw bytes
func NewSliceReaderFromBytes(data []byte) (*SliceReader, error) {
	if len(data) < HeaderSize {
		return nil, fmt.Errorf("insufficient data for header: got %d bytes, need %d", len(data), HeaderSize)
	}

	// Parse header
	header, err := ParseHeader(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse header: %w", err)
	}

	if err := header.Validate(); err != nil {
		return nil, fmt.Errorf("invalid header: %w", err)
	}

	// Parse slice entries
	sliceCount := int(header.SliceCount)
	entriesEnd := HeaderSize + sliceCount*EntrySize

	if len(data) < entriesEnd {
		return nil, fmt.Errorf("slice index truncated: expected %d bytes, got %d", entriesEnd, len(data))
	}

	entries := make([]*SliceEntry, 0, sliceCount)
	for i := 0; i < sliceCount; i++ {
		offset := HeaderSize + i*EntrySize
		entry, err := ParseEntry(data[offset:])
		if err != nil {
			return nil, fmt.Errorf("failed to parse entry %d: %w", i, err)
		}
		entries = append(entries, entry)
	}

	return &SliceReader{
		data:    data,
		header:  header,
		entries: entries,
	}, nil
}

// NewSliceReaderFromGzip loads a SliceReader from gzip-compressed bytes
func NewSliceReaderFromGzip(gzipData []byte) (*SliceReader, error) {
	gr, err := gzip.NewReader(bytes.NewReader(gzipData))
	if err != nil {
		return nil, fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gr.Close()

	data, err := io.ReadAll(gr)
	if err != nil {
		return nil, fmt.Errorf("failed to decompress gzip data: %w", err)
	}

	return NewSliceReaderFromBytes(data)
}

// NewSliceReaderFromFile loads a SliceReader from a file (auto-detects gzip)
func NewSliceReaderFromFile(path string) (*SliceReader, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	// Check if it's gzipped (magic bytes: 0x1f 0x8b)
	if len(data) >= 2 && data[0] == 0x1f && data[1] == 0x8b {
		return NewSliceReaderFromGzip(data)
	}

	return NewSliceReaderFromBytes(data)
}

// Fallback returns the fallback target as uint8
func (r *SliceReader) Fallback() uint8 {
	return r.header.Fallback()
}

// SliceCount returns the number of slices
func (r *SliceReader) SliceCount() int {
	return len(r.entries)
}

// MatchDomain matches a domain against all domain slices
// Returns the target of the first matching slice, or nil if no match
func (r *SliceReader) MatchDomain(domain string) *uint8 {
	normalized := strings.ToLower(domain)

	for _, entry := range r.entries {
		if entry.GetType() != SliceTypeFstDomain {
			continue
		}

		if r.matchDomainInSlice(entry, normalized) {
			target := entry.GetTarget()
			return &target
		}
	}

	return nil
}

// MatchIP matches an IP address against all IP slices
// Returns the target of the first matching slice, or nil if no match
func (r *SliceReader) MatchIP(ip net.IP) *uint8 {
	for _, entry := range r.entries {
		switch entry.GetType() {
		case SliceTypeCidrV4:
			if ip4 := ip.To4(); ip4 != nil {
				ipv4 := ipToUint32(ip4)
				if r.matchCidrV4InSlice(entry, ipv4) {
					target := entry.GetTarget()
					return &target
				}
			}
		case SliceTypeCidrV6:
			if ip16 := ip.To16(); ip16 != nil {
				if r.matchCidrV6InSlice(entry, [16]byte(ip16)) {
					target := entry.GetTarget()
					return &target
				}
			}
		}
	}

	return nil
}

// MatchGeoIP matches a GeoIP country code against all GeoIP slices
// Returns the target of the first matching slice, or nil if no match
func (r *SliceReader) MatchGeoIP(country string) *uint8 {
	countryUpper := strings.ToUpper(country)
	countryBytes := []byte(countryUpper)

	for _, entry := range r.entries {
		if entry.GetType() != SliceTypeGeoIP {
			continue
		}

		if r.matchGeoIPInSlice(entry, countryBytes) {
			target := entry.GetTarget()
			return &target
		}
	}

	return nil
}

// matchDomainInSlice matches a domain within a single FST domain slice
func (r *SliceReader) matchDomainInSlice(entry *SliceEntry, domain string) bool {
	offset := int(entry.Offset)
	size := int(entry.Size)

	if offset+size > len(r.data) {
		return false
	}

	fstData := r.data[offset : offset+size]

	// Create FST from data
	fst, err := NewFSTReader(fstData)
	if err != nil {
		return false
	}

	// Try exact match (reversed with dot prefix)
	withDot := "." + domain
	reversed := reverseString(withDot)
	if fst.Contains([]byte(reversed)) {
		return true
	}

	// Check parent domains for suffix match
	parts := strings.Split(domain, ".")
	for i := 1; i < len(parts); i++ {
		suffix := strings.Join(parts[i:], ".")
		suffixWithDot := "." + suffix
		reversedSuffix := reverseString(suffixWithDot)
		if fst.Contains([]byte(reversedSuffix)) {
			return true
		}
	}

	return false
}

// matchCidrV4InSlice matches an IPv4 address within a single CIDR v4 slice
func (r *SliceReader) matchCidrV4InSlice(entry *SliceEntry, ip uint32) bool {
	offset := int(entry.Offset)
	count := int(entry.Count)

	// Each entry is 8 bytes: network (4) + prefix_len (1) + padding (3)
	for i := 0; i < count; i++ {
		entryOffset := offset + i*8
		if entryOffset+8 > len(r.data) {
			break
		}

		// Network is in big-endian (network byte order)
		network := uint32(r.data[entryOffset])<<24 |
			uint32(r.data[entryOffset+1])<<16 |
			uint32(r.data[entryOffset+2])<<8 |
			uint32(r.data[entryOffset+3])

		prefixLen := r.data[entryOffset+4]

		// Calculate mask
		var mask uint32
		if prefixLen == 0 {
			mask = 0
		} else if prefixLen >= 32 {
			mask = ^uint32(0)
		} else {
			mask = ^uint32(0) << (32 - prefixLen)
		}

		if (ip & mask) == (network & mask) {
			return true
		}
	}

	return false
}

// matchCidrV6InSlice matches an IPv6 address within a single CIDR v6 slice
func (r *SliceReader) matchCidrV6InSlice(entry *SliceEntry, ip [16]byte) bool {
	offset := int(entry.Offset)
	count := int(entry.Count)

	// Each entry is 24 bytes: network (16) + prefix_len (1) + padding (7)
	for i := 0; i < count; i++ {
		entryOffset := offset + i*24
		if entryOffset+24 > len(r.data) {
			break
		}

		var network [16]byte
		copy(network[:], r.data[entryOffset:entryOffset+16])
		prefixLen := r.data[entryOffset+16]

		if matchesIPv6CIDR(&ip, &network, prefixLen) {
			return true
		}
	}

	return false
}

// matchGeoIPInSlice matches a country code within a single GeoIP slice
func (r *SliceReader) matchGeoIPInSlice(entry *SliceEntry, country []byte) bool {
	offset := int(entry.Offset)
	count := int(entry.Count)

	// Each entry is 4 bytes: country_code (2) + padding (2)
	for i := 0; i < count; i++ {
		entryOffset := offset + i*4
		if entryOffset+4 > len(r.data) {
			break
		}

		storedCountry := r.data[entryOffset : entryOffset+2]
		if len(country) >= 2 && storedCountry[0] == country[0] && storedCountry[1] == country[1] {
			return true
		}
	}

	return false
}

// Helper functions

func ipToUint32(ip net.IP) uint32 {
	if len(ip) == 16 {
		ip = ip[12:16]
	}
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

func matchesIPv6CIDR(ip, network *[16]byte, prefixLen uint8) bool {
	fullBytes := int(prefixLen / 8)
	remainingBits := int(prefixLen % 8)

	// Compare full bytes
	if fullBytes > 0 {
		for i := 0; i < fullBytes; i++ {
			if ip[i] != network[i] {
				return false
			}
		}
	}

	// Compare remaining bits
	if remainingBits > 0 && fullBytes < 16 {
		mask := uint8(0xFF << (8 - remainingBits))
		if (ip[fullBytes] & mask) != (network[fullBytes] & mask) {
			return false
		}
	}

	return true
}

func reverseString(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}
