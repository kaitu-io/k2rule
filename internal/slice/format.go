package slice

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"time"
)

// Constants for the K2Rule slice format
const (
	// Magic bytes for K2Rule v2 slice-based format
	Magic = "K2RULEV2"
	// FormatVersion is the current format version
	FormatVersion = 1
	// HeaderSize is the size of SliceHeader in bytes
	HeaderSize = 64
	// EntrySize is the size of SliceEntry in bytes
	EntrySize = 16
)

// SliceType represents different types of slices in the format
type SliceType uint8

const (
	// SliceTypeFstDomain is FST-based domain set
	SliceTypeFstDomain SliceType = 0x01
	// SliceTypeCidrV4 is IPv4 CIDR ranges
	SliceTypeCidrV4 SliceType = 0x02
	// SliceTypeCidrV6 is IPv6 CIDR ranges
	SliceTypeCidrV6 SliceType = 0x03
	// SliceTypeGeoIP is GeoIP country codes
	SliceTypeGeoIP SliceType = 0x04
	// SliceTypeExactIPv4 is exact IPv4 addresses
	SliceTypeExactIPv4 SliceType = 0x05
	// SliceTypeExactIPv6 is exact IPv6 addresses
	SliceTypeExactIPv6 SliceType = 0x06
)

// String returns the string representation of SliceType
func (t SliceType) String() string {
	switch t {
	case SliceTypeFstDomain:
		return "FstDomain"
	case SliceTypeCidrV4:
		return "CidrV4"
	case SliceTypeCidrV6:
		return "CidrV6"
	case SliceTypeGeoIP:
		return "GeoIP"
	case SliceTypeExactIPv4:
		return "ExactIPv4"
	case SliceTypeExactIPv6:
		return "ExactIPv6"
	default:
		return fmt.Sprintf("Unknown(%d)", t)
	}
}

// SliceHeader represents the file header (64 bytes)
type SliceHeader struct {
	Magic          [8]byte  // "K2RULEV2"
	Version        uint32   // Format version
	SliceCount     uint32   // Number of slices
	FallbackTarget uint8    // Fallback target when no rule matches
	_reserved1     [3]byte  // Reserved padding
	Timestamp      int64    // Unix timestamp
	Checksum       [16]byte // SHA-256 checksum (first 16 bytes)
	_reserved2     [16]byte // Reserved for future use
}

// Validate validates the header
func (h *SliceHeader) Validate() error {
	if string(h.Magic[:]) != Magic {
		return fmt.Errorf("invalid magic: got %q, want %q", h.Magic[:], Magic)
	}
	if h.Version > FormatVersion {
		return fmt.Errorf("unsupported version: %d (max supported: %d)", h.Version, FormatVersion)
	}
	return nil
}

// Fallback returns the fallback target as uint8
func (h *SliceHeader) Fallback() uint8 {
	return h.FallbackTarget
}

// Time returns the timestamp as time.Time
func (h *SliceHeader) Time() time.Time {
	return time.Unix(h.Timestamp, 0)
}

// SliceEntry represents a slice index entry (16 bytes)
type SliceEntry struct {
	SliceType  uint8    // Slice type
	Target     uint8    // Target for this slice
	_reserved  [2]byte  // Reserved
	Offset     uint32   // Offset to slice data (from file start)
	Size       uint32   // Size of slice data
	Count      uint32   // Number of entries in this slice
}

// GetType returns the SliceType
func (e *SliceEntry) GetType() SliceType {
	return SliceType(e.SliceType)
}

// GetTarget returns the Target as uint8
func (e *SliceEntry) GetTarget() uint8 {
	return e.Target
}

// ParseHeader parses a SliceHeader from bytes (little-endian)
func ParseHeader(data []byte) (*SliceHeader, error) {
	if len(data) < HeaderSize {
		return nil, fmt.Errorf("insufficient data for header: got %d bytes, need %d", len(data), HeaderSize)
	}

	var h SliceHeader
	buf := bytes.NewReader(data[:HeaderSize])

	// Read fields in order
	if err := binary.Read(buf, binary.LittleEndian, &h.Magic); err != nil {
		return nil, fmt.Errorf("failed to read magic: %w", err)
	}
	if err := binary.Read(buf, binary.LittleEndian, &h.Version); err != nil {
		return nil, fmt.Errorf("failed to read version: %w", err)
	}
	if err := binary.Read(buf, binary.LittleEndian, &h.SliceCount); err != nil {
		return nil, fmt.Errorf("failed to read slice_count: %w", err)
	}
	if err := binary.Read(buf, binary.LittleEndian, &h.FallbackTarget); err != nil {
		return nil, fmt.Errorf("failed to read fallback_target: %w", err)
	}
	if err := binary.Read(buf, binary.LittleEndian, &h._reserved1); err != nil {
		return nil, fmt.Errorf("failed to read reserved1: %w", err)
	}
	if err := binary.Read(buf, binary.LittleEndian, &h.Timestamp); err != nil {
		return nil, fmt.Errorf("failed to read timestamp: %w", err)
	}
	if err := binary.Read(buf, binary.LittleEndian, &h.Checksum); err != nil {
		return nil, fmt.Errorf("failed to read checksum: %w", err)
	}
	if err := binary.Read(buf, binary.LittleEndian, &h._reserved2); err != nil {
		return nil, fmt.Errorf("failed to read reserved2: %w", err)
	}

	return &h, nil
}

// ParseEntry parses a SliceEntry from bytes (little-endian)
func ParseEntry(data []byte) (*SliceEntry, error) {
	if len(data) < EntrySize {
		return nil, fmt.Errorf("insufficient data for entry: got %d bytes, need %d", len(data), EntrySize)
	}

	var e SliceEntry
	buf := bytes.NewReader(data[:EntrySize])

	if err := binary.Read(buf, binary.LittleEndian, &e.SliceType); err != nil {
		return nil, fmt.Errorf("failed to read slice_type: %w", err)
	}
	if err := binary.Read(buf, binary.LittleEndian, &e.Target); err != nil {
		return nil, fmt.Errorf("failed to read target: %w", err)
	}
	if err := binary.Read(buf, binary.LittleEndian, &e._reserved); err != nil {
		return nil, fmt.Errorf("failed to read reserved: %w", err)
	}
	if err := binary.Read(buf, binary.LittleEndian, &e.Offset); err != nil {
		return nil, fmt.Errorf("failed to read offset: %w", err)
	}
	if err := binary.Read(buf, binary.LittleEndian, &e.Size); err != nil {
		return nil, fmt.Errorf("failed to read size: %w", err)
	}
	if err := binary.Read(buf, binary.LittleEndian, &e.Count); err != nil {
		return nil, fmt.Errorf("failed to read count: %w", err)
	}

	return &e, nil
}
