package k2rule

import (
	"compress/gzip"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/oschwald/geoip2-golang"
)

// DefaultGeoIPURL is the default MaxMind GeoLite2 Country database URL
const DefaultGeoIPURL = "https://cdn.jsdelivr.net/npm/geolite2-country/GeoLite2-Country.mmdb.gz"

// GeoIPManager manages the GeoIP database with auto-download and hot-reload
type GeoIPManager struct {
	url      string
	cacheDir string
	reader   *geoip2.Reader

	// Update metadata
	mu         sync.RWMutex
	etag       string
	lastUpdate time.Time
	stopCh     chan struct{}
}

// NewGeoIPManager creates a new GeoIP manager
func NewGeoIPManager(url, cacheDir string) *GeoIPManager {
	if url == "" {
		url = DefaultGeoIPURL
	}

	if cacheDir == "" {
		homeDir, _ := os.UserHomeDir()
		cacheDir = filepath.Join(homeDir, ".cache", "k2rule")
	}

	return &GeoIPManager{
		url:      url,
		cacheDir: cacheDir,
		stopCh:   make(chan struct{}),
	}
}

// Init initializes the GeoIP manager: checks cache → downloads if needed → starts auto-update
func (m *GeoIPManager) Init() error {
	// Create cache directory
	if err := os.MkdirAll(m.cacheDir, 0755); err != nil {
		return fmt.Errorf("failed to create cache directory: %w", err)
	}

	// 1. Check cache
	cachedPath := m.getCachePath()
	if _, err := os.Stat(cachedPath); err == nil {
		// Cache exists, try to load it
		if err := m.loadDatabase(cachedPath); err == nil {
			// Successfully loaded from cache, start background update check
			go m.startAutoUpdate()
			return nil
		}
		// Cache corrupted, will re-download
	}

	// 2. Cache doesn't exist or is corrupted, force download
	if err := m.downloadAndLoad(false); err != nil {
		return fmt.Errorf("failed to download GeoIP database: %w", err)
	}

	// 3. Start auto-update
	go m.startAutoUpdate()

	return nil
}

// Stop stops the auto-update background task
func (m *GeoIPManager) Stop() {
	close(m.stopCh)
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.reader != nil {
		m.reader.Close()
		m.reader = nil
	}
}

// LookupCountry looks up the ISO country code for an IP address
// Returns the 2-letter country code (e.g., "US", "CN") or error if not found
func (m *GeoIPManager) LookupCountry(ip net.IP) (string, error) {
	m.mu.RLock()
	reader := m.reader
	m.mu.RUnlock()

	if reader == nil {
		return "", fmt.Errorf("GeoIP database not loaded")
	}

	record, err := reader.Country(ip)
	if err != nil {
		return "", fmt.Errorf("GeoIP lookup failed: %w", err)
	}

	if record.Country.IsoCode == "" {
		return "", fmt.Errorf("no country found for IP")
	}

	return record.Country.IsoCode, nil
}

// downloadAndLoad downloads the GeoIP database and loads it
func (m *GeoIPManager) downloadAndLoad(useETag bool) error {
	req, err := http.NewRequest("GET", m.url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// ETag optimization: 304 Not Modified
	m.mu.RLock()
	currentETag := m.etag
	m.mu.RUnlock()

	if useETag && currentETag != "" {
		req.Header.Set("If-None-Match", currentETag)
	}

	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to download: %w", err)
	}
	defer resp.Body.Close()

	// 304 Not Modified - no need to update
	if resp.StatusCode == http.StatusNotModified {
		return nil
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	// Download to temporary file
	tmpPath := m.getCachePath() + ".tmp"
	tmpFile, err := os.Create(tmpPath)
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}

	// Decompress gzip if URL ends with .gz
	var reader io.Reader = resp.Body
	if filepath.Ext(m.url) == ".gz" {
		gzReader, err := gzip.NewReader(resp.Body)
		if err != nil {
			tmpFile.Close()
			os.Remove(tmpPath)
			return fmt.Errorf("failed to create gzip reader: %w", err)
		}
		defer gzReader.Close()
		reader = gzReader
	}

	_, err = io.Copy(tmpFile, reader)
	tmpFile.Close()
	if err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("failed to write temp file: %w", err)
	}

	// Atomic rename (overwrite old cache)
	cachePath := m.getCachePath()
	if err := os.Rename(tmpPath, cachePath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("failed to rename temp file: %w", err)
	}

	// Hot-reload (atomic swap)
	if err := m.loadDatabase(cachePath); err != nil {
		return fmt.Errorf("failed to load new database: %w", err)
	}

	// Update metadata
	m.mu.Lock()
	m.etag = resp.Header.Get("ETag")
	m.lastUpdate = time.Now()
	m.mu.Unlock()

	return nil
}

// loadDatabase loads a GeoIP database from a file
func (m *GeoIPManager) loadDatabase(path string) error {
	reader, err := geoip2.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open GeoIP database: %w", err)
	}

	// Atomic swap
	m.mu.Lock()
	oldReader := m.reader
	m.reader = reader
	m.mu.Unlock()

	// Close old reader after swap
	if oldReader != nil {
		oldReader.Close()
	}

	return nil
}

// startAutoUpdate runs background auto-update (every 7 days)
func (m *GeoIPManager) startAutoUpdate() {
	ticker := time.NewTicker(7 * 24 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Check for updates (use ETag)
			m.downloadAndLoad(true)
		case <-m.stopCh:
			return
		}
	}
}

// getCachePath returns the cache file path (based on URL hash)
func (m *GeoIPManager) getCachePath() string {
	hash := sha256.Sum256([]byte(m.url))
	filename := fmt.Sprintf("%x.mmdb", hash[:8])
	return filepath.Join(m.cacheDir, filename)
}

// GetETag returns the current ETag
func (m *GeoIPManager) GetETag() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.etag
}

// GetLastUpdate returns the last update time
func (m *GeoIPManager) GetLastUpdate() time.Time {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.lastUpdate
}
