package slice

import (
	"compress/gzip"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"

	mmap "github.com/edsrzf/mmap-go"
)

// MmapReader provides zero-copy access to K2Rule files using memory-mapped I/O
type MmapReader struct {
	file    *os.File      // File handle
	data    mmap.MMap     // Memory-mapped region (zero-copy)
	size    int64         // File size
	header  *SliceHeader  // Parsed header (resident in memory ~64 bytes)
	entries []*SliceEntry // Slice entries (resident in memory ~100s of bytes)
}

// NewMmapReader creates a new mmap reader from an uncompressed file
func NewMmapReader(path string) (*MmapReader, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}

	stat, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, fmt.Errorf("failed to stat file: %w", err)
	}
	size := stat.Size()

	if size == 0 {
		file.Close()
		return nil, fmt.Errorf("file is empty")
	}

	// Memory-map the file (zero-copy on all platforms)
	data, err := mmap.Map(file, mmap.RDONLY, 0)
	if err != nil {
		file.Close()
		return nil, fmt.Errorf("failed to mmap file: %w", err)
	}

	reader := &MmapReader{
		file: file,
		data: data,
		size: size,
	}

	// Parse header and entries (resident in memory)
	if err := reader.parseHeaderAndEntries(); err != nil {
		reader.Close()
		return nil, err
	}

	return reader, nil
}

// NewMmapReaderFromGzip creates a mmap reader from a gzip-compressed file
// It decompresses to a temporary file first, then mmaps it
func NewMmapReaderFromGzip(gzipPath string) (*MmapReader, error) {
	// 1. Calculate SHA256 hash as temp file name (avoid duplicate decompression)
	hash, err := computeFileSHA256(gzipPath)
	if err != nil {
		return nil, fmt.Errorf("failed to compute file hash: %w", err)
	}
	tmpPath := filepath.Join(filepath.Dir(gzipPath), fmt.Sprintf("k2rule-%s.bin", hash))

	// 2. Check if temp file already exists (cache hit)
	if _, err := os.Stat(tmpPath); err == nil {
		// Temp file exists, directly mmap it
		return NewMmapReader(tmpPath)
	}

	// 3. Decompress gzip to temp file
	if err := decompressGzip(gzipPath, tmpPath); err != nil {
		return nil, fmt.Errorf("failed to decompress gzip: %w", err)
	}

	// 4. Mmap the temp file
	return NewMmapReader(tmpPath)
}

// Close unmaps the memory and closes the file
func (r *MmapReader) Close() error {
	var err error
	if r.data != nil {
		if unmapErr := r.data.Unmap(); unmapErr != nil {
			err = unmapErr
		}
		r.data = nil
	}
	if r.file != nil {
		if closeErr := r.file.Close(); closeErr != nil && err == nil {
			err = closeErr
		}
		r.file = nil
	}
	return err
}

// parseHeaderAndEntries parses header and slice entries (resident in memory)
func (r *MmapReader) parseHeaderAndEntries() error {
	if len(r.data) < HeaderSize {
		return fmt.Errorf("insufficient data for header: got %d bytes, need %d", len(r.data), HeaderSize)
	}

	// Parse header
	header, err := ParseHeader(r.data)
	if err != nil {
		return fmt.Errorf("failed to parse header: %w", err)
	}

	if err := header.Validate(); err != nil {
		return fmt.Errorf("invalid header: %w", err)
	}

	r.header = header

	// Parse slice entries
	sliceCount := int(header.SliceCount)
	entriesEnd := HeaderSize + sliceCount*EntrySize

	if len(r.data) < entriesEnd {
		return fmt.Errorf("slice index truncated: expected %d bytes, got %d", entriesEnd, len(r.data))
	}

	entries := make([]*SliceEntry, 0, sliceCount)
	for i := 0; i < sliceCount; i++ {
		offset := HeaderSize + i*EntrySize
		entry, err := ParseEntry(r.data[offset:])
		if err != nil {
			return fmt.Errorf("failed to parse entry %d: %w", i, err)
		}
		entries = append(entries, entry)
	}

	r.entries = entries
	return nil
}

// getSliceData returns a zero-copy slice view into the mmap region
func (r *MmapReader) getSliceData(entry *SliceEntry) []byte {
	offset := int(entry.Offset)
	size := int(entry.Size)

	// Zero-copy: return a slice view into the mmap region
	if offset+size > len(r.data) {
		return nil
	}
	return r.data[offset : offset+size]
}

// Fallback returns the fallback target
func (r *MmapReader) Fallback() uint8 {
	if r.header == nil {
		return 0
	}
	return r.header.Fallback()
}

// SliceCount returns the number of slices
func (r *MmapReader) SliceCount() int {
	return len(r.entries)
}

// MatchDomain matches a domain against all domain slices (zero-copy)
func (r *MmapReader) MatchDomain(domain string) *uint8 {
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

// MatchIP matches an IP address against all IP slices (zero-copy)
func (r *MmapReader) MatchIP(ip net.IP) *uint8 {
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

// MatchGeoIP matches a GeoIP country code (zero-copy)
func (r *MmapReader) MatchGeoIP(country string) *uint8 {
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

// matchDomainInSlice matches a domain within a single FST domain slice (zero-copy)
func (r *MmapReader) matchDomainInSlice(entry *SliceEntry, domain string) bool {
	// Zero-copy: get FST data as a slice view
	fstData := r.getSliceData(entry)
	if fstData == nil {
		return false
	}

	// Create FST from mmap data (no additional copy)
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

// matchCidrV4InSlice matches an IPv4 address within a single CIDR v4 slice (zero-copy)
func (r *MmapReader) matchCidrV4InSlice(entry *SliceEntry, ip uint32) bool {
	offset := int(entry.Offset)
	count := int(entry.Count)

	// Each entry is 8 bytes: network (4) + prefix_len (1) + padding (3)
	for i := 0; i < count; i++ {
		entryOffset := offset + i*8
		if entryOffset+8 > len(r.data) {
			break
		}

		// Zero-copy: directly access mmap region
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

// matchCidrV6InSlice matches an IPv6 address within a single CIDR v6 slice (zero-copy)
func (r *MmapReader) matchCidrV6InSlice(entry *SliceEntry, ip [16]byte) bool {
	offset := int(entry.Offset)
	count := int(entry.Count)

	// Each entry is 24 bytes: network (16) + prefix_len (1) + padding (7)
	for i := 0; i < count; i++ {
		entryOffset := offset + i*24
		if entryOffset+24 > len(r.data) {
			break
		}

		// Zero-copy: directly access mmap region
		var network [16]byte
		copy(network[:], r.data[entryOffset:entryOffset+16])
		prefixLen := r.data[entryOffset+16]

		if matchesIPv6CIDR(&ip, &network, prefixLen) {
			return true
		}
	}

	return false
}

// matchGeoIPInSlice matches a country code within a single GeoIP slice (zero-copy)
func (r *MmapReader) matchGeoIPInSlice(entry *SliceEntry, country []byte) bool {
	offset := int(entry.Offset)
	count := int(entry.Count)

	// Each entry is 4 bytes: country_code (2) + padding (2)
	for i := 0; i < count; i++ {
		entryOffset := offset + i*4
		if entryOffset+4 > len(r.data) {
			break
		}

		// Zero-copy: directly access mmap region
		storedCountry := r.data[entryOffset : entryOffset+2]
		if len(country) >= 2 && storedCountry[0] == country[0] && storedCountry[1] == country[1] {
			return true
		}
	}

	return false
}

// Helper functions

func computeFileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", hash.Sum(nil)[:16]), nil
}

func decompressGzip(gzipPath, outPath string) error {
	gzFile, err := os.Open(gzipPath)
	if err != nil {
		return err
	}
	defer gzFile.Close()

	gzReader, err := gzip.NewReader(gzFile)
	if err != nil {
		return err
	}
	defer gzReader.Close()

	outFile, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer outFile.Close()

	_, err = io.Copy(outFile, gzReader)
	return err
}
