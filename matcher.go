package k2rule

import (
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/kaitu-io/k2rule/internal/slice"
)

var (
	globalManager *RemoteRuleManager
	globalMatcher *Matcher
	globalMutex   sync.RWMutex
)

// Matcher provides rule matching functionality
type Matcher struct {
	reader      *slice.SliceReader
	pornChecker *PornChecker
}

// InitRemote initializes from a remote URL with auto-download and updates
// This is the recommended way to use k2rule - provides out-of-the-box functionality
// The fallback target is automatically read from the .k2r file header.
//
// Parameters:
//   - url: CDN URL of the rule file (e.g., https://cdn.jsdelivr.net/gh/kaitu-io/k2rule@release/cn_blacklist.k2r.gz)
//   - cacheDir: Cache directory path. Use "" for default (~/.cache/k2rule/).
//               For iOS, use Library/Caches subdirectory to prevent iCloud sync.
//
// Example (default cache):
//   k2rule.InitRemote("https://...", "")
//
// Example (iOS custom cache):
//   k2rule.InitRemote("https://...", "/path/to/Library/Caches/k2rule")
func InitRemote(url string, cacheDir string) error {
	globalMutex.Lock()
	defer globalMutex.Unlock()

	// Create manager with default fallback (will be synced from file)
	manager := NewRemoteRuleManager(url, cacheDir, TargetDirect)
	if err := manager.Init(); err != nil {
		return err
	}

	// Fallback is automatically synced from file in Init()
	globalManager = manager
	return nil
}

// Init initializes the global matcher with default settings
// This is a convenience function that uses the zero-value fallback (Direct)
func Init() error {
	return InitWithFallback(TargetDirect)
}

// InitWithFallback initializes the global matcher with a specific fallback target
func InitWithFallback(fallback Target) error {
	matcher := &Matcher{}
	setGlobalMatcher(matcher)
	return nil
}

// InitFromFile initializes from a local k2r file using memory-mapped I/O
// The fallback target is automatically read from the .k2r file header.
//
// Parameters:
//   - path: Path to the .k2r or .k2r.gz file
//
// Example:
//   k2rule.InitFromFile("./rules/cn_blacklist.k2r.gz")
func InitFromFile(path string) error {
	globalMutex.Lock()
	defer globalMutex.Unlock()

	// Create manager with default fallback (will be synced from file)
	manager := NewRemoteRuleManager("", "", TargetDirect)

	// Load the local file directly
	if err := manager.reader.Load(path); err != nil {
		return fmt.Errorf("failed to load k2r file: %w", err)
	}

	// Sync fallback from loaded file
	manager.fallback = Target(manager.reader.Fallback())

	globalManager = manager
	return nil
}

// InitFromBytes initializes the global matcher from k2r bytes
func InitFromBytes(data []byte) error {
	reader, err := slice.NewSliceReaderFromBytes(data)
	if err != nil {
		return fmt.Errorf("failed to load k2r data: %w", err)
	}

	matcher := &Matcher{
		reader: reader,
	}

	setGlobalMatcher(matcher)
	return nil
}

// InitPornChecker initializes the porn checker from a file
func InitPornChecker(fstPath string) error {
	pornChecker, err := NewPornCheckerFromFile(fstPath)
	if err != nil {
		return fmt.Errorf("failed to load porn checker: %w", err)
	}

	globalMutex.Lock()
	defer globalMutex.Unlock()

	if globalMatcher == nil {
		globalMatcher = &Matcher{}
	}
	globalMatcher.pornChecker = pornChecker

	return nil
}

// Match automatically matches input (domain or IP) and returns the target
func Match(input string) Target {
	globalMutex.RLock()
	manager := globalManager
	matcher := globalMatcher
	globalMutex.RUnlock()

	// Prefer RemoteRuleManager if available (mmap-based)
	if manager != nil {
		// Try to parse as IP first
		if ip := net.ParseIP(input); ip != nil {
			return manager.MatchIP(ip)
		}
		// Treat as domain
		return manager.MatchDomain(input)
	}

	// Fallback to old matcher
	if matcher == nil || matcher.reader == nil {
		return TargetDirect
	}

	// Try to parse as IP first
	if ip := net.ParseIP(input); ip != nil {
		if target := matcher.reader.MatchIP(ip); target != nil {
			return Target(*target)
		}
		return Target(matcher.reader.Fallback())
	}

	// Treat as domain
	if target := matcher.reader.MatchDomain(input); target != nil {
		return Target(*target)
	}

	return Target(matcher.reader.Fallback())
}

// MatchDomain matches a domain and returns the target
func MatchDomain(domain string) Target {
	globalMutex.RLock()
	manager := globalManager
	matcher := globalMatcher
	globalMutex.RUnlock()

	// Prefer RemoteRuleManager (mmap-based)
	if manager != nil {
		return manager.MatchDomain(domain)
	}

	// Fallback to old matcher
	if matcher == nil || matcher.reader == nil {
		return TargetDirect
	}

	if target := matcher.reader.MatchDomain(domain); target != nil {
		return Target(*target)
	}

	return Target(matcher.reader.Fallback())
}

// MatchIP matches an IP address and returns the target
func MatchIP(ip net.IP) Target {
	globalMutex.RLock()
	manager := globalManager
	matcher := globalMatcher
	globalMutex.RUnlock()

	// Prefer RemoteRuleManager (mmap-based)
	if manager != nil {
		return manager.MatchIP(ip)
	}

	// Fallback to old matcher
	if matcher == nil || matcher.reader == nil {
		return TargetDirect
	}

	if target := matcher.reader.MatchIP(ip); target != nil {
		return Target(*target)
	}

	return Target(matcher.reader.Fallback())
}

// MatchGeoIP matches a GeoIP country code and returns the target
func MatchGeoIP(country string) Target {
	globalMutex.RLock()
	manager := globalManager
	matcher := globalMatcher
	globalMutex.RUnlock()

	// Prefer RemoteRuleManager (mmap-based)
	if manager != nil {
		return manager.MatchGeoIP(country)
	}

	// Fallback to old matcher
	if matcher == nil || matcher.reader == nil {
		return TargetDirect
	}

	if target := matcher.reader.MatchGeoIP(country); target != nil {
		return Target(*target)
	}

	return Target(matcher.reader.Fallback())
}

// IsPorn checks if a domain is a porn domain using the global porn checker
func IsPorn(domain string) bool {
	matcher := getGlobalMatcher()
	if matcher == nil || matcher.pornChecker == nil {
		// Fallback to heuristic only
		return IsPornHeuristic(domain)
	}

	return matcher.pornChecker.IsPorn(domain)
}

// Helper functions

func setGlobalMatcher(matcher *Matcher) {
	globalMutex.Lock()
	defer globalMutex.Unlock()
	globalMatcher = matcher
}

func getGlobalMatcher() *Matcher {
	globalMutex.RLock()
	defer globalMutex.RUnlock()
	return globalMatcher
}

// IsIPAddress checks if a string is an IP address
func IsIPAddress(s string) bool {
	return net.ParseIP(s) != nil
}

// IsDomain checks if a string is likely a domain name
func IsDomain(s string) bool {
	// Simple heuristic: contains dots and no colons (not IPv6)
	return strings.Contains(s, ".") && !strings.Contains(s, ":")
}
