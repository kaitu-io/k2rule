package k2rule

import (
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/kaitu-io/k2rule/internal/slice"
	"github.com/oschwald/geoip2-golang"
)

var (
	globalConfig      *Config             // Single source of truth for configuration
	globalManager     *RemoteRuleManager
	globalGeoIPMgr    *GeoIPManager
	globalPornManager *PornRemoteManager
	globalMatcher     *Matcher
	globalMutex       sync.RWMutex
	globalTmpRules    sync.Map // key: string (input), value: Target
)

// Matcher provides rule matching functionality
type Matcher struct {
	reader      *slice.SliceReader
	pornChecker *PornChecker
}

// Init initializes K2Rule with unified configuration.
// This is the recommended way to initialize K2Rule - provides a single configuration
// interface for all components (rules, GeoIP, porn detection).
//
// The config is saved as the single source of truth and can be retrieved with GetConfig().
//
// Examples:
//
//	// Full configuration with rules + GeoIP + porn detection
//	config := &k2rule.Config{
//	    RuleURL:  "https://cdn.jsdelivr.net/gh/kaitu-io/k2rule@release/cn_blacklist.k2r.gz",
//	    GeoIPURL: "",  // Use default MaxMind GeoLite2
//	    PornURL:  "",  // Use default porn database
//	    CacheDir: "",  // Use default ~/.cache/k2rule/
//	}
//	k2rule.Init(config)
//
//	// Pure global mode (no rules, VPN-style)
//	config := &k2rule.Config{
//	    IsGlobal:     true,
//	    GlobalTarget: k2rule.TargetProxy,
//	}
//	k2rule.Init(config)
//
//	// Rule-based mode with runtime toggle
//	config := &k2rule.Config{
//	    RuleURL:  "https://.../rules.k2r.gz",
//	    IsGlobal: false,  // Start in rule-based mode
//	}
//	k2rule.Init(config)
//	k2rule.ToggleGlobal(true)  // Switch to global mode at runtime
func Init(config *Config) error {
	if config == nil {
		return fmt.Errorf("config cannot be nil")
	}

	// Validate config
	if err := config.Validate(); err != nil {
		return err
	}

	// Set defaults
	config.SetDefaults()

	globalMutex.Lock()
	defer globalMutex.Unlock()

	// Save config as source of truth
	globalConfig = config

	// Initialize rule manager
	// Priority: RuleFile > RuleURL (empty RuleURL uses default)
	if config.RuleFile != "" {
		// Load from local file
		manager := NewRemoteRuleManager("", config.CacheDir, TargetDirect)
		if err := manager.reader.Load(config.RuleFile); err != nil {
			return fmt.Errorf("failed to load rule file: %w", err)
		}
		manager.fallback = Target(manager.reader.Fallback())
		globalManager = manager
	} else if !config.IsGlobal {
		// Not in pure global mode, load rules from URL (empty URL uses default)
		url := defaultIfEmpty(config.RuleURL, DefaultRuleURL)
		manager := NewRemoteRuleManager(url, config.CacheDir, TargetDirect)
		if err := manager.Init(); err != nil {
			return fmt.Errorf("failed to init rules: %w", err)
		}
		globalManager = manager
	}

	// Initialize GeoIP (Priority: GeoIPFile > GeoIPURL)
	if config.GeoIPFile != "" {
		reader, err := geoip2.Open(config.GeoIPFile)
		if err != nil {
			return fmt.Errorf("failed to open GeoIP file: %w", err)
		}
		globalGeoIPMgr = &GeoIPManager{
			reader: reader,
			stopCh: make(chan struct{}),
		}
	} else {
		url := defaultIfEmpty(config.GeoIPURL, DefaultGeoIPURL)
		geoIPMgr := NewGeoIPManager(url, config.CacheDir)
		if err := geoIPMgr.Init(); err != nil {
			return fmt.Errorf("failed to init GeoIP: %w", err)
		}
		globalGeoIPMgr = geoIPMgr
	}

	// Initialize porn detection (Priority: PornFile > PornURL)
	if config.PornFile != "" {
		checker, err := NewPornCheckerFromFile(config.PornFile)
		if err != nil {
			return fmt.Errorf("failed to load porn file: %w", err)
		}
		if globalMatcher == nil {
			globalMatcher = &Matcher{}
		}
		globalMatcher.pornChecker = checker
	} else {
		url := defaultIfEmpty(config.PornURL, DefaultPornURL)
		pornMgr := NewPornRemoteManager(url, config.CacheDir)
		if err := pornMgr.Init(); err != nil {
			return fmt.Errorf("failed to init porn detection: %w", err)
		}
		globalPornManager = pornMgr
	}

	return nil
}

// ToggleGlobal switches global proxy mode on/off (immediate effect).
// Changes take effect immediately without requiring a restart.
//
// When enabled (true):
//   - All traffic goes to GlobalTarget (except LAN IPs, which always go to DIRECT)
//   - Rules are ignored (but still loaded)
//
// When disabled (false):
//   - Rule-based routing is used
//   - Match() checks domain/IP-CIDR/GeoIP rules
//
// Example:
//
//	k2rule.ToggleGlobal(true)   // Switch to global proxy mode
//	k2rule.Match("google.com")  // → GlobalTarget (e.g., PROXY)
//	k2rule.Match("192.168.1.1") // → DIRECT (LAN bypass)
//
//	k2rule.ToggleGlobal(false)  // Back to rule-based mode
//	k2rule.Match("google.com")  // → Check rules
func ToggleGlobal(enabled bool) {
	globalMutex.Lock()
	defer globalMutex.Unlock()

	if globalConfig != nil {
		globalConfig.IsGlobal = enabled
	}
}

// SetGlobalTarget sets the target for global proxy mode.
// Only affects behavior when IsGlobal = true.
//
// Example:
//
//	k2rule.SetGlobalTarget(k2rule.TargetReject)  // Block all in global mode
//	k2rule.ToggleGlobal(true)                    // Enable global mode
//	k2rule.Match("anything.com")                 // → REJECT
func SetGlobalTarget(target Target) {
	globalMutex.Lock()
	defer globalMutex.Unlock()

	if globalConfig != nil {
		globalConfig.GlobalTarget = target
	}
}

// GetConfig returns a copy of the current configuration.
// Returns a copy to prevent external modification of the internal config.
//
// Example:
//
//	config := k2rule.GetConfig()
//	fmt.Printf("Global mode: %v\n", config.IsGlobal)
//	fmt.Printf("Cache dir: %s\n", config.CacheDir)
func GetConfig() Config {
	globalMutex.RLock()
	defer globalMutex.RUnlock()

	if globalConfig == nil {
		return Config{}
	}

	// Return a copy to prevent external modification
	return *globalConfig
}

// UpdateConfig hot-reloads the configuration without restarting.
// This re-initializes all components with the new configuration.
// Useful for dynamic configuration changes at runtime.
//
// Example:
//
//	newConfig := &k2rule.Config{
//	    RuleURL:  "https://new-rules.k2r.gz",
//	    IsGlobal: false,
//	}
//	k2rule.UpdateConfig(newConfig)
func UpdateConfig(config *Config) error {
	if config == nil {
		return fmt.Errorf("config cannot be nil")
	}

	if err := config.Validate(); err != nil {
		return err
	}

	config.SetDefaults()

	// Re-initialize with new config
	return Init(config)
}

// Match performs intelligent routing based on input type and configuration.
// This is the recommended method for all matching.
//
// Priority (from highest to lowest):
//  1. LAN/Private IPs → DIRECT (hardcoded, always bypassed)
//  2. TmpRule → Exact match override (set via SetTmpRule)
//  3. Global mode → GlobalTarget (if IsGlobal = true)
//  4. Rule matching → Domain/IP-CIDR/GeoIP rules
//  5. Fallback → Rule file fallback or GlobalTarget
//
// Handles:
//   - Automatic type detection (domain/IPv4/IPv6)
//   - LAN IP bypass (192.168.x.x, 10.x.x.x, etc.)
//   - Global proxy mode toggle
//   - IP-CIDR rule matching
//   - Automatic GeoIP lookup (if initialized)
//   - Domain rule matching
//
// Example:
//
//	target := k2rule.Match("google.com")    // Domain matching
//	target := k2rule.Match("8.8.8.8")       // IP matching + GeoIP
//	target := k2rule.Match("192.168.1.1")   // → DIRECT (LAN bypass)
//	target := k2rule.Match("::1")           // → DIRECT (IPv6 loopback)
func Match(input string) Target {
	globalMutex.RLock()
	config := globalConfig
	manager := globalManager
	geoIPMgr := globalGeoIPMgr
	matcher := globalMatcher
	globalMutex.RUnlock()

	// Step 1: Try to parse as IP
	if ip := net.ParseIP(input); ip != nil {
		// Step 1a: Check private/LAN IP (hardcoded bypass - highest priority)
		if isPrivateIP(ip) {
			return TargetDirect
		}

		// Step 1b: Check TmpRule (exact match, higher priority than Global/static)
		if target, ok := globalTmpRules.Load(input); ok {
			return target.(Target)
		}

		// Step 1c: Check global mode
		if config != nil && config.IsGlobal {
			return config.GlobalTarget
		}

		// Step 1d: Check IP-CIDR rules (if rules loaded)
		if manager != nil {
			if target := manager.matchIPCIDR(ip); target != manager.fallback {
				return target
			}

			// Step 1e: Check GeoIP rules (if GeoIP initialized)
			if geoIPMgr != nil {
				if country, err := geoIPMgr.LookupCountry(ip); err == nil {
					if target := manager.matchGeoIP(country); target != manager.fallback {
						return target
					}
				}
			}

			// Step 1f: Return fallback
			return manager.fallback
		}

		// Fallback to old matcher (if no RemoteRuleManager)
		if matcher != nil && matcher.reader != nil {
			// Check IP-CIDR rules
			if target := matcher.reader.MatchIP(ip); target != nil {
				return Target(*target)
			}

			// Check GeoIP rules (if GeoIP initialized)
			if geoIPMgr != nil {
				if country, err := geoIPMgr.LookupCountry(ip); err == nil {
					if target := matcher.reader.MatchGeoIP(country); target != nil {
						return Target(*target)
					}
				}
			}

			return Target(matcher.reader.Fallback())
		}

		// No rules loaded, use config fallback
		if config != nil {
			return config.GlobalTarget
		}

		return TargetDirect
	}

	// Step 2: Treat as domain
	// Step 2a: Check TmpRule (exact match, higher priority than Global/static)
	if target, ok := globalTmpRules.Load(input); ok {
		return target.(Target)
	}

	// Step 2b: Check global mode
	if config != nil && config.IsGlobal {
		return config.GlobalTarget
	}

	// Step 2c: Check domain rules (if rules loaded)
	if manager != nil {
		if target := manager.matchDomain(input); target != manager.fallback {
			return target
		}
		return manager.fallback
	}

	// Fallback to old matcher (if no RemoteRuleManager)
	if matcher != nil && matcher.reader != nil {
		if target := matcher.reader.MatchDomain(input); target != nil {
			return Target(*target)
		}
		return Target(matcher.reader.Fallback())
	}

	// No rules loaded, use config fallback
	if config != nil {
		return config.GlobalTarget
	}

	return TargetDirect
}

// MatchDomain matches a domain and returns the target.
//
// Deprecated: Use Match() instead, which automatically detects input type.
// This function will be removed in v1.0.0.
func MatchDomain(domain string) Target {
	return Match(domain)
}

// MatchIP matches an IP address and returns the target.
//
// Deprecated: Use Match() instead, which automatically detects input type
// and performs GeoIP lookup if initialized.
// This function will be removed in v1.0.0.
func MatchIP(ip net.IP) Target {
	return Match(ip.String())
}

// MatchGeoIP matches a GeoIP country code and returns the target.
//
// Deprecated: GeoIP lookup is now automatic when using Match() with an IP address.
// Initialize GeoIP with InitGeoIP() and use Match() instead.
// This function will be removed in v1.0.0.
func MatchGeoIP(country string) Target {
	globalMutex.RLock()
	manager := globalManager
	matcher := globalMatcher
	globalMutex.RUnlock()

	// Prefer RemoteRuleManager (mmap-based)
	if manager != nil {
		return manager.matchGeoIP(country)
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

// IsPorn checks if a domain is a porn domain using the global porn checker.
// Uses the remote porn manager if initialized with InitPorn()/InitPornRemote(),
// otherwise falls back to the old porn checker or heuristic-only detection.
func IsPorn(domain string) bool {
	globalMutex.RLock()
	pornManager := globalPornManager
	matcher := globalMatcher
	globalMutex.RUnlock()

	// Prefer PornRemoteManager if available
	if pornManager != nil {
		return pornManager.IsPorn(domain)
	}

	// Fallback to old porn checker
	if matcher != nil && matcher.pornChecker != nil {
		return matcher.pornChecker.IsPorn(domain)
	}

	// Fallback to heuristic only
	return IsPornHeuristic(domain)
}

// SetTmpRule sets a temporary rule override for the given input (IP or domain).
// TmpRule has higher priority than Global mode and static rules, but lower than LAN bypass.
// If the static rules already return the same target, the override is not stored (storage optimization).
func SetTmpRule(input string, target Target) {
	// Storage optimization: skip storing if static rules already return the same target
	// AND global mode is not active (since TmpRule must override Global mode).
	globalMutex.RLock()
	isGlobal := globalConfig != nil && globalConfig.IsGlobal
	globalMutex.RUnlock()

	if !isGlobal {
		staticTarget := matchStaticRules(input)
		if staticTarget == target {
			globalTmpRules.Delete(input) // clear any existing override
			return
		}
	}
	globalTmpRules.Store(input, target)
}

// ClearTmpRule removes a single temporary rule override.
func ClearTmpRule(input string) {
	globalTmpRules.Delete(input)
}

// ClearTmpRules removes all temporary rule overrides.
func ClearTmpRules() {
	globalTmpRules.Range(func(key, _ any) bool {
		globalTmpRules.Delete(key)
		return true
	})
}

// matchStaticRules matches input against static rules only (IP-CIDR / GeoIP / Domain).
// Does not check LAN, Global mode, or TmpRule — used by SetTmpRule for storage optimization.
func matchStaticRules(input string) Target {
	globalMutex.RLock()
	manager := globalManager
	geoIPMgr := globalGeoIPMgr
	globalMutex.RUnlock()

	if manager == nil {
		return TargetDirect
	}

	if ip := net.ParseIP(input); ip != nil {
		if target := manager.matchIPCIDR(ip); target != manager.fallback {
			return target
		}
		if geoIPMgr != nil {
			if country, err := geoIPMgr.LookupCountry(ip); err == nil {
				if target := manager.matchGeoIP(country); target != manager.fallback {
					return target
				}
			}
		}
		return manager.fallback
	}

	if target := manager.matchDomain(input); target != manager.fallback {
		return target
	}
	return manager.fallback
}

// Helper functions

// defaultIfEmpty returns defaultValue if value is empty, otherwise returns value
func defaultIfEmpty(value, defaultValue string) string {
	if value == "" {
		return defaultValue
	}
	return value
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
