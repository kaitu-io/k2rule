package slice

import (
	"net"
	"os"
	"sync/atomic"
	"time"
)

// CachedMmapReader provides lock-free hot-reload support for MmapReader
// using atomic.Value for zero-lock concurrent access
type CachedMmapReader struct {
	current    atomic.Value  // Stores *MmapReader
	generation atomic.Uint64 // Version number for debugging/monitoring
}

// NewCachedMmapReader creates a new cached mmap reader
func NewCachedMmapReader() *CachedMmapReader {
	return &CachedMmapReader{}
}

// Load loads or reloads a rule file with atomic hot-swap
// Old readers are closed with a grace period to allow ongoing reads to complete
func (c *CachedMmapReader) Load(path string) error {
	newReader, err := NewMmapReaderFromGzip(path)
	if err != nil {
		return err
	}

	// Atomic swap (lock-free)
	oldReader := c.current.Swap(newReader)
	c.generation.Add(1)

	// Delayed close of old reader (grace period for ongoing reads)
	if oldReader != nil {
		go func() {
			time.Sleep(5 * time.Second) // Allow ongoing reads to complete
			oldReader.(*MmapReader).Close()
		}()
	}

	return nil
}

// LoadFromBytes loads from raw bytes (for testing or embedded rules)
func (c *CachedMmapReader) LoadFromBytes(data []byte) error {
	// For bytes, we need to create a temporary file
	// This is less efficient but maintains compatibility
	tmpFile, err := createTempFileFromBytes(data)
	if err != nil {
		return err
	}

	newReader, err := NewMmapReader(tmpFile)
	if err != nil {
		return err
	}

	// Atomic swap
	oldReader := c.current.Swap(newReader)
	c.generation.Add(1)

	// Delayed close
	if oldReader != nil {
		go func() {
			time.Sleep(5 * time.Second)
			oldReader.(*MmapReader).Close()
		}()
	}

	return nil
}

// Get returns the current reader (lock-free)
func (c *CachedMmapReader) Get() *MmapReader {
	val := c.current.Load()
	if val == nil {
		return nil
	}
	return val.(*MmapReader)
}

// Generation returns the current generation number
func (c *CachedMmapReader) Generation() uint64 {
	return c.generation.Load()
}

// Close closes the current reader
func (c *CachedMmapReader) Close() error {
	reader := c.Get()
	if reader == nil {
		return nil
	}
	return reader.Close()
}

// Matching methods (delegate to current reader)

// Fallback returns the fallback target
func (c *CachedMmapReader) Fallback() uint8 {
	reader := c.Get()
	if reader == nil {
		return 0
	}
	return reader.Fallback()
}

// SliceCount returns the number of slices
func (c *CachedMmapReader) SliceCount() int {
	reader := c.Get()
	if reader == nil {
		return 0
	}
	return reader.SliceCount()
}

// MatchDomain matches a domain (zero-copy, lock-free)
func (c *CachedMmapReader) MatchDomain(domain string) *uint8 {
	reader := c.Get()
	if reader == nil {
		return nil
	}
	return reader.MatchDomain(domain)
}

// MatchIP matches an IP address (zero-copy, lock-free)
func (c *CachedMmapReader) MatchIP(ip net.IP) *uint8 {
	reader := c.Get()
	if reader == nil {
		return nil
	}
	return reader.MatchIP(ip)
}

// MatchGeoIP matches a GeoIP country code (zero-copy, lock-free)
func (c *CachedMmapReader) MatchGeoIP(country string) *uint8 {
	reader := c.Get()
	if reader == nil {
		return nil
	}
	return reader.MatchGeoIP(country)
}

// Helper function

func createTempFileFromBytes(data []byte) (string, error) {
	tmpFile, err := os.CreateTemp("", "k2rule-*.bin")
	if err != nil {
		return "", err
	}
	defer tmpFile.Close()

	if _, err := tmpFile.Write(data); err != nil {
		os.Remove(tmpFile.Name())
		return "", err
	}

	return tmpFile.Name(), nil
}
