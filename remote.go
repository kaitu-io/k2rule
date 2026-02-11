package k2rule

import (
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/kaitu-io/k2rule/internal/slice"
)

// RemoteRuleManager manages remote rule files with auto-download and hot-reload
type RemoteRuleManager struct {
	url         string                    // Rule file URL
	cacheDir    string                    // Cache directory (~/.cache/k2rule)
	reader      *slice.CachedMmapReader   // Hot-reload capable reader
	fallback    Target                    // Default fallback target

	// Update metadata
	mu          sync.RWMutex
	etag        string                    // Current ETag
	lastUpdate  time.Time                 // Last update time
	stopCh      chan struct{}             // Stop channel for auto-update
}

// NewRemoteRuleManager creates a new remote rule manager
func NewRemoteRuleManager(url, cacheDir string, fallback Target) *RemoteRuleManager {
	if cacheDir == "" {
		homeDir, _ := os.UserHomeDir()
		cacheDir = filepath.Join(homeDir, ".cache", "k2rule")
	}

	return &RemoteRuleManager{
		url:      url,
		cacheDir: cacheDir,
		fallback: fallback,
		reader:   slice.NewCachedMmapReader(),
		stopCh:   make(chan struct{}),
	}
}

// Init initializes the manager: checks cache → downloads if needed → starts auto-update
func (m *RemoteRuleManager) Init() error {
	// Create cache directory
	if err := os.MkdirAll(m.cacheDir, 0755); err != nil {
		return fmt.Errorf("failed to create cache directory: %w", err)
	}

	// 1. Check cache
	cachedPath := m.getCachePath()
	if _, err := os.Stat(cachedPath); err == nil {
		// Cache exists, try to load it
		if err := m.reader.Load(cachedPath); err == nil {
			// Successfully loaded from cache, start background update check
			go m.startAutoUpdate()
			return nil
		}
		// Cache corrupted, will re-download
	}

	// 2. Cache doesn't exist or is corrupted, force download
	if err := m.downloadAndLoad(false); err != nil {
		return fmt.Errorf("failed to download rules: %w", err)
	}

	// 3. Start auto-update
	go m.startAutoUpdate()

	return nil
}

// Stop stops the auto-update background task
func (m *RemoteRuleManager) Stop() {
	close(m.stopCh)
}

// Update manually triggers a rule update check
func (m *RemoteRuleManager) Update() error {
	return m.downloadAndLoad(true)
}

// downloadAndLoad downloads the rule file and loads it
func (m *RemoteRuleManager) downloadAndLoad(useETag bool) error {
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

	client := &http.Client{Timeout: 60 * time.Second}
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

	_, err = io.Copy(tmpFile, resp.Body)
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
	if err := m.reader.Load(cachePath); err != nil {
		return fmt.Errorf("failed to load new rules: %w", err)
	}

	// Update metadata
	m.mu.Lock()
	m.etag = resp.Header.Get("ETag")
	m.lastUpdate = time.Now()
	m.mu.Unlock()

	return nil
}

// startAutoUpdate runs background auto-update (every 6 hours)
func (m *RemoteRuleManager) startAutoUpdate() {
	ticker := time.NewTicker(6 * time.Hour)
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
func (m *RemoteRuleManager) getCachePath() string {
	hash := sha256.Sum256([]byte(m.url))
	filename := fmt.Sprintf("%x.k2r.gz", hash[:8])
	return filepath.Join(m.cacheDir, filename)
}

// GetETag returns the current ETag
func (m *RemoteRuleManager) GetETag() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.etag
}

// GetLastUpdate returns the last update time
func (m *RemoteRuleManager) GetLastUpdate() time.Time {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.lastUpdate
}

// GetGeneration returns the current rule generation
func (m *RemoteRuleManager) GetGeneration() uint64 {
	return m.reader.Generation()
}

// Matching methods (delegate to reader)

// MatchDomain matches a domain
func (m *RemoteRuleManager) MatchDomain(domain string) Target {
	target := m.reader.MatchDomain(domain)
	if target == nil {
		return m.fallback
	}
	return Target(*target)
}

// MatchIP matches an IP address
func (m *RemoteRuleManager) MatchIP(ip net.IP) Target {
	target := m.reader.MatchIP(ip)
	if target == nil {
		return m.fallback
	}
	return Target(*target)
}

// MatchGeoIP matches a GeoIP country code
func (m *RemoteRuleManager) MatchGeoIP(country string) Target {
	target := m.reader.MatchGeoIP(country)
	if target == nil {
		return m.fallback
	}
	return Target(*target)
}

// Fallback returns the fallback target
func (m *RemoteRuleManager) Fallback() Target {
	return m.fallback
}

// Close closes the manager and reader
func (m *RemoteRuleManager) Close() error {
	m.Stop()
	return m.reader.Close()
}
