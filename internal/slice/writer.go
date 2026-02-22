package slice

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
	"time"
)

// sliceData holds a slice's entry and raw data before final layout is computed.
type sliceData struct {
	entry SliceEntry
	data  []byte
}

// SliceWriter builds K2RULEV2 format binary files.
//
// It supports adding domain slices (stored as sorted list for binary search),
// IPv4/IPv6 CIDR slices, and GeoIP slices. The fallback target is embedded
// in the header and used when no slice matches.
type SliceWriter struct {
	fallback uint8
	slices   []sliceData
}

// NewSliceWriter creates a new SliceWriter with the given fallback target.
//
// Fallback target constants: Direct=0, Proxy=1, Reject=2.
func NewSliceWriter(fallback uint8) *SliceWriter {
	return &SliceWriter{
		fallback: fallback,
		slices:   make([]sliceData, 0),
	}
}

// AddDomainSlice adds a domain slice using sorted list storage (SliceTypeSortedDomain).
//
// Domains are normalized to lowercase, deduplicated, and sorted. Each domain is
// stored with a leading dot for suffix matching semantics (e.g., ".example.com"
// matches "example.com" and "sub.example.com"). An empty domain list is a no-op.
func (w *SliceWriter) AddDomainSlice(domains []string, target uint8) error {
	if len(domains) == 0 {
		return nil
	}

	// Normalize, add leading dot, deduplicate, sort
	seen := make(map[string]struct{}, len(domains))
	normalized := make([]string, 0, len(domains))
	for _, d := range domains {
		lower := strings.ToLower(d)
		if lower == "" {
			continue
		}
		var withDot string
		if strings.HasPrefix(lower, ".") {
			withDot = lower
		} else {
			withDot = "." + lower
		}
		if _, exists := seen[withDot]; !exists {
			seen[withDot] = struct{}{}
			normalized = append(normalized, withDot)
		}
	}

	if len(normalized) == 0 {
		return nil
	}

	sort.Strings(normalized)

	// Encode as sorted list: [count:4][len:4][data][len:4][data]...
	// Each entry: 4-byte uint32 length (little-endian) followed by domain bytes.
	var buf bytes.Buffer

	countBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(countBytes, uint32(len(normalized)))
	buf.Write(countBytes)

	for _, domain := range normalized {
		domainBytes := []byte(domain)
		lenBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(lenBytes, uint32(len(domainBytes)))
		buf.Write(lenBytes)
		buf.Write(domainBytes)
	}

	data := buf.Bytes()

	entry := SliceEntry{
		SliceType: uint8(SliceTypeSortedDomain),
		Target:    target,
		Count:     uint32(len(normalized)),
	}

	w.slices = append(w.slices, sliceData{
		entry: entry,
		data:  data,
	})

	return nil
}

// AddCidrV4Slice adds an IPv4 CIDR slice.
//
// Each CIDR is represented as (network_u32, prefix_len). Entries are stored
// in big-endian network byte order (8 bytes each: 4 network + 1 prefix_len + 3 padding).
func (w *SliceWriter) AddCidrV4Slice(cidrs []CidrV4Entry, target uint8) error {
	if len(cidrs) == 0 {
		return nil
	}

	sorted := make([]CidrV4Entry, len(cidrs))
	copy(sorted, cidrs)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Network < sorted[j].Network
	})

	// Each entry: 4 bytes network (BE) + 1 byte prefix_len + 3 bytes padding = 8 bytes
	data := make([]byte, len(sorted)*8)
	for i, cidr := range sorted {
		offset := i * 8
		binary.BigEndian.PutUint32(data[offset:], cidr.Network)
		data[offset+4] = cidr.PrefixLen
		// padding bytes 5,6,7 are zero
	}

	entry := SliceEntry{
		SliceType: uint8(SliceTypeCidrV4),
		Target:    target,
		Count:     uint32(len(sorted)),
	}

	w.slices = append(w.slices, sliceData{entry: entry, data: data})
	return nil
}

// AddCidrV6Slice adds an IPv6 CIDR slice.
//
// Each CIDR is represented as (network_bytes[16], prefix_len). Entries are stored
// as 24 bytes each: 16 network bytes + 1 prefix_len + 7 bytes padding.
func (w *SliceWriter) AddCidrV6Slice(cidrs []CidrV6Entry, target uint8) error {
	if len(cidrs) == 0 {
		return nil
	}

	sorted := make([]CidrV6Entry, len(cidrs))
	copy(sorted, cidrs)
	sort.Slice(sorted, func(i, j int) bool {
		return bytes.Compare(sorted[i].Network[:], sorted[j].Network[:]) < 0
	})

	// Each entry: 16 bytes network + 1 byte prefix_len + 7 bytes padding = 24 bytes
	data := make([]byte, len(sorted)*24)
	for i, cidr := range sorted {
		offset := i * 24
		copy(data[offset:], cidr.Network[:])
		data[offset+16] = cidr.PrefixLen
		// padding bytes 17-23 are zero
	}

	entry := SliceEntry{
		SliceType: uint8(SliceTypeCidrV6),
		Target:    target,
		Count:     uint32(len(sorted)),
	}

	w.slices = append(w.slices, sliceData{entry: entry, data: data})
	return nil
}

// AddGeoIPSlice adds a GeoIP country code slice.
//
// Countries are 2-letter ISO country codes (case-insensitive). Each entry is
// stored as 4 bytes: 2 code bytes (uppercase) + 2 bytes padding.
func (w *SliceWriter) AddGeoIPSlice(countries []string, target uint8) error {
	if len(countries) == 0 {
		return nil
	}

	// Each entry: 2-byte country code + 2-byte padding = 4 bytes
	data := make([]byte, len(countries)*4)
	for i, country := range countries {
		upper := strings.ToUpper(country)
		bs := []byte(upper)
		offset := i * 4
		if len(bs) >= 1 {
			data[offset] = bs[0]
		}
		if len(bs) >= 2 {
			data[offset+1] = bs[1]
		}
		// padding bytes 2,3 are zero
	}

	entry := SliceEntry{
		SliceType: uint8(SliceTypeGeoIP),
		Target:    target,
		Count:     uint32(len(countries)),
	}

	w.slices = append(w.slices, sliceData{entry: entry, data: data})
	return nil
}

// Build finalizes the binary layout and returns the complete K2RULEV2 binary.
//
// The layout is: Header (64 bytes) + SliceEntries (16 bytes each) + Slice data.
// The checksum in the header covers the complete file content.
func (w *SliceWriter) Build() ([]byte, error) {
	sliceCount := len(w.slices)

	// Calculate data start offset (after header + slice index)
	dataStart := HeaderSize + sliceCount*EntrySize

	// Assign offsets and sizes to each slice entry
	currentOffset := dataStart
	for i := range w.slices {
		w.slices[i].entry.Offset = uint32(currentOffset)
		w.slices[i].entry.Size = uint32(len(w.slices[i].data))
		currentOffset += len(w.slices[i].data)
	}

	totalSize := currentOffset
	output := make([]byte, totalSize)

	// Write header (64 bytes):
	// [0:8]   Magic "K2RULEV2"
	// [8:12]  Version (uint32 LE)
	// [12:16] SliceCount (uint32 LE)
	// [16]    FallbackTarget
	// [17:20] Reserved1 (3 bytes)
	// [20:28] Timestamp (int64 LE)
	// [28:44] Checksum (16 bytes, SHA-256 prefix)
	// [44:64] Reserved2 (20 bytes)
	copy(output[0:8], []byte(Magic))
	binary.LittleEndian.PutUint32(output[8:12], FormatVersion)
	binary.LittleEndian.PutUint32(output[12:16], uint32(sliceCount))
	output[16] = w.fallback
	// reserved1 bytes 17,18,19 = 0
	timestamp := time.Now().Unix()
	binary.LittleEndian.PutUint64(output[20:28], uint64(timestamp))
	// checksum will be filled in below
	// reserved2 bytes 44:64 = 0

	// Write slice index entries (16 bytes each)
	for i, sd := range w.slices {
		entryOffset := HeaderSize + i*EntrySize
		if err := writeSliceEntry(output[entryOffset:entryOffset+EntrySize], &sd.entry); err != nil {
			return nil, fmt.Errorf("write entry %d: %w", i, err)
		}
	}

	// Write slice data
	for _, sd := range w.slices {
		copy(output[sd.entry.Offset:sd.entry.Offset+sd.entry.Size], sd.data)
	}

	// Compute SHA-256 checksum of the entire output (with zeroed checksum field)
	// then embed first 16 bytes
	checksum := sha256.Sum256(output)
	copy(output[28:44], checksum[:16])

	return output, nil
}

// writeSliceEntry serializes a SliceEntry to a 16-byte buffer in little-endian format.
func writeSliceEntry(buf []byte, e *SliceEntry) error {
	if len(buf) < EntrySize {
		return fmt.Errorf("buffer too small: need %d bytes, got %d", EntrySize, len(buf))
	}
	buf[0] = e.SliceType
	buf[1] = e.Target
	buf[2] = 0 // reserved
	buf[3] = 0 // reserved
	binary.LittleEndian.PutUint32(buf[4:8], e.Offset)
	binary.LittleEndian.PutUint32(buf[8:12], e.Size)
	binary.LittleEndian.PutUint32(buf[12:16], e.Count)
	return nil
}

// CidrV4Entry represents an IPv4 CIDR block for AddCidrV4Slice.
type CidrV4Entry struct {
	Network   uint32 // Network address as uint32 (host byte order)
	PrefixLen uint8  // Prefix length (0-32)
}

// CidrV6Entry represents an IPv6 CIDR block for AddCidrV6Slice.
type CidrV6Entry struct {
	Network   [16]byte // Network address bytes
	PrefixLen uint8    // Prefix length (0-128)
}
