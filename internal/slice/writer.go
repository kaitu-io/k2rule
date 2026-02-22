package slice

import (
	"encoding/binary"
	"sort"
	"strings"
	"time"
)

// CidrV4Entry represents a single IPv4 CIDR entry.
type CidrV4Entry struct {
	Network   uint32 // IPv4 network address in host byte order
	PrefixLen uint8  // Prefix length (0-32)
}

// CidrV6Entry represents a single IPv6 CIDR entry.
type CidrV6Entry struct {
	Network   [16]byte // IPv6 network address
	PrefixLen uint8    // Prefix length (0-128)
}

// sliceRecord holds the pending data for one slice before Build is called.
type sliceRecord struct {
	sliceType uint8
	target    uint8
	data      []byte
	count     uint32
}

// SliceWriter builds K2RULEV3 binary files with sorted domain slices.
type SliceWriter struct {
	fallbackTarget uint8
	slices         []sliceRecord
}

// NewSliceWriter creates a new SliceWriter with the given fallback target.
func NewSliceWriter(fallbackTarget uint8) *SliceWriter {
	return &SliceWriter{
		fallbackTarget: fallbackTarget,
		slices:         make([]sliceRecord, 0),
	}
}

// normalizeDomain converts a domain to its normalized form:
// lowercase, dot-prefixed (exactly one leading dot), reversed.
// Returns the normalized string.
func normalizeDomain(domain string) string {
	lower := strings.ToLower(domain)
	// Ensure exactly one leading dot
	withDot := lower
	if !strings.HasPrefix(withDot, ".") {
		withDot = "." + lower
	}
	return reverseString(withDot)
}

// AddDomainSlice normalizes, sorts, and deduplicates the provided domains,
// then appends a SortedDomain slice entry to the writer.
func (w *SliceWriter) AddDomainSlice(domains []string, target uint8) error {
	// Normalize all domains
	normalized := make([]string, 0, len(domains))
	for _, d := range domains {
		n := normalizeDomain(d)
		normalized = append(normalized, n)
	}

	// Sort lexicographically
	sort.Strings(normalized)

	// Dedup
	deduped := normalized[:0]
	for i, s := range normalized {
		if i == 0 || s != normalized[i-1] {
			deduped = append(deduped, s)
		}
	}

	count := uint32(len(deduped))

	// Build binary layout:
	// count (4 bytes LE)
	// offsets[0..count-1] (4 bytes each LE)
	// sentinel (4 bytes LE) = total strings length
	// strings area (variable)
	stringsArea := strings.Join(deduped, "")
	stringsLen := uint32(len(stringsArea))

	// Total header = 4 + (count+1)*4
	headerBytes := 4 + (count+1)*4
	totalSize := headerBytes + stringsLen

	buf := make([]byte, totalSize)

	binary.LittleEndian.PutUint32(buf[0:4], count)

	var currentOffset uint32
	for i, s := range deduped {
		binary.LittleEndian.PutUint32(buf[4+uint32(i)*4:], currentOffset)
		currentOffset += uint32(len(s))
	}
	// Sentinel: total strings length
	binary.LittleEndian.PutUint32(buf[4+count*4:], stringsLen)

	// Write strings area
	copy(buf[headerBytes:], stringsArea)

	w.slices = append(w.slices, sliceRecord{
		sliceType: uint8(SliceTypeSortedDomain),
		target:    target,
		data:      buf,
		count:     count,
	})
	return nil
}

// AddCidrV4Slice appends a CidrV4 slice entry.
// Each entry is written as 8 bytes: network (BE 4 bytes) + prefix_len (1 byte) + 3 padding bytes.
func (w *SliceWriter) AddCidrV4Slice(cidrs []CidrV4Entry, target uint8) error {
	count := uint32(len(cidrs))
	buf := make([]byte, count*8)

	for i, cidr := range cidrs {
		offset := i * 8
		// Network in big-endian byte order
		buf[offset] = byte(cidr.Network >> 24)
		buf[offset+1] = byte(cidr.Network >> 16)
		buf[offset+2] = byte(cidr.Network >> 8)
		buf[offset+3] = byte(cidr.Network)
		buf[offset+4] = cidr.PrefixLen
		// padding [5..7] already zero
	}

	w.slices = append(w.slices, sliceRecord{
		sliceType: uint8(SliceTypeCidrV4),
		target:    target,
		data:      buf,
		count:     count,
	})
	return nil
}

// AddCidrV6Slice appends a CidrV6 slice entry.
// Each entry is written as 24 bytes: network (16 bytes) + prefix_len (1 byte) + 7 padding bytes.
func (w *SliceWriter) AddCidrV6Slice(cidrs []CidrV6Entry, target uint8) error {
	count := uint32(len(cidrs))
	buf := make([]byte, count*24)

	for i, cidr := range cidrs {
		offset := i * 24
		copy(buf[offset:offset+16], cidr.Network[:])
		buf[offset+16] = cidr.PrefixLen
		// padding [17..23] already zero
	}

	w.slices = append(w.slices, sliceRecord{
		sliceType: uint8(SliceTypeCidrV6),
		target:    target,
		data:      buf,
		count:     count,
	})
	return nil
}

// AddGeoIPSlice appends a GeoIP slice entry.
// Each country code is stored as 2 uppercase bytes + 2 padding bytes (4 bytes total).
func (w *SliceWriter) AddGeoIPSlice(countries []string, target uint8) error {
	count := uint32(len(countries))
	buf := make([]byte, count*4)

	for i, country := range countries {
		upper := strings.ToUpper(country)
		offset := i * 4
		if len(upper) >= 2 {
			buf[offset] = upper[0]
			buf[offset+1] = upper[1]
		} else if len(upper) == 1 {
			buf[offset] = upper[0]
		}
		// padding [2..3] already zero
	}

	w.slices = append(w.slices, sliceRecord{
		sliceType: uint8(SliceTypeGeoIP),
		target:    target,
		data:      buf,
		count:     count,
	})
	return nil
}

// Build assembles the full binary file: header (64 bytes) + slice index (16 bytes each) + slice data.
// Returns the complete binary representation.
func (w *SliceWriter) Build() ([]byte, error) {
	sliceCount := uint32(len(w.slices))

	// Calculate offsets for each slice data section
	// Data begins after header + slice index
	dataStart := uint32(HeaderSize) + sliceCount*uint32(EntrySize)

	offsets := make([]uint32, sliceCount)
	currentOffset := dataStart
	for i, s := range w.slices {
		offsets[i] = currentOffset
		currentOffset += uint32(len(s.data))
	}

	totalSize := int(currentOffset)
	out := make([]byte, totalSize)

	// --- Write header (64 bytes) ---
	// Magic [8]byte
	copy(out[0:8], "K2RULEV3")
	// Version uint32 LE
	binary.LittleEndian.PutUint32(out[8:12], FormatVersion)
	// SliceCount uint32 LE
	binary.LittleEndian.PutUint32(out[12:16], sliceCount)
	// FallbackTarget uint8
	out[16] = w.fallbackTarget
	// Reserved [3]byte at 17..19 (already zero)
	// Timestamp int64 LE at 20..27
	ts := time.Now().Unix()
	binary.LittleEndian.PutUint64(out[20:28], uint64(ts))
	// Checksum [16]byte at 28..43 (zero for now — reserved for future use)
	// Reserved [16]byte at 44..59 (already zero)

	// --- Write slice index (16 bytes per entry) ---
	for i, s := range w.slices {
		base := HeaderSize + i*EntrySize
		out[base] = s.sliceType          // SliceType uint8
		out[base+1] = s.target           // Target uint8
		// Reserved [2]byte at base+2..base+3 (zero)
		binary.LittleEndian.PutUint32(out[base+4:base+8], offsets[i])   // Offset uint32
		binary.LittleEndian.PutUint32(out[base+8:base+12], uint32(len(s.data))) // Size uint32
		binary.LittleEndian.PutUint32(out[base+12:base+16], s.count)    // Count uint32
	}

	// --- Write slice data ---
	for i, s := range w.slices {
		start := int(offsets[i])
		copy(out[start:start+len(s.data)], s.data)
	}

	return out, nil
}
