package k2rule

import (
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// DefaultPornURL is the default porn domain FST database URL
const DefaultPornURL = "https://cdn.jsdelivr.net/gh/kaitu-io/k2rule@release/porn_domains.fst.gz"

// PornRemoteManager manages the porn database with auto-download and hot-reload
type PornRemoteManager struct {
	url      string
	cacheDir string
	checker  *PornChecker

	// Update metadata
	mu         sync.RWMutex
	etag       string
	lastUpdate time.Time
	stopCh     chan struct{}
}

// NewPornRemoteManager creates a new porn remote manager
func NewPornRemoteManager(url, cacheDir string) *PornRemoteManager {
	if url == "" {
		url = DefaultPornURL
	}

	if cacheDir == "" {
		homeDir, _ := os.UserHomeDir()
		cacheDir = filepath.Join(homeDir, ".cache", "k2rule")
	}

	return &PornRemoteManager{
		url:      url,
		cacheDir: cacheDir,
		stopCh:   make(chan struct{}),
	}
}

// Init initializes the manager: checks cache → downloads if needed → starts auto-update
func (m *PornRemoteManager) Init() error {
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
		return fmt.Errorf("failed to download porn database: %w", err)
	}

	// 3. Start auto-update
	go m.startAutoUpdate()

	return nil
}

// Stop stops the auto-update background task
func (m *PornRemoteManager) Stop() {
	close(m.stopCh)
}

// Update manually triggers a database update check
func (m *PornRemoteManager) Update() error {
	return m.downloadAndLoad(true)
}

// IsPorn checks if a domain is a porn domain
func (m *PornRemoteManager) IsPorn(domain string) bool {
	m.mu.RLock()
	checker := m.checker
	m.mu.RUnlock()

	if checker == nil {
		// Fallback to heuristic only
		return IsPornHeuristic(domain)
	}

	return checker.IsPorn(domain)
}

// downloadAndLoad downloads the porn database and loads it
func (m *PornRemoteManager) downloadAndLoad(useETag bool) error {
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

// loadDatabase loads a porn database from a gzip file
func (m *PornRemoteManager) loadDatabase(path string) error {
	// The file is gzipped, use NewPornCheckerFromFile which handles decompression
	checker, err := NewPornCheckerFromFile(path)
	if err != nil {
		return fmt.Errorf("failed to load porn database: %w", err)
	}

	// Atomic swap
	m.mu.Lock()
	m.checker = checker
	m.mu.Unlock()

	return nil
}

// startAutoUpdate runs background auto-update (every 6 hours)
func (m *PornRemoteManager) startAutoUpdate() {
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
func (m *PornRemoteManager) getCachePath() string {
	hash := sha256.Sum256([]byte(m.url))
	filename := fmt.Sprintf("%x.fst.gz", hash[:8])
	return filepath.Join(m.cacheDir, filename)
}

// GetETag returns the current ETag
func (m *PornRemoteManager) GetETag() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.etag
}

// GetLastUpdate returns the last update time
func (m *PornRemoteManager) GetLastUpdate() time.Time {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.lastUpdate
}
