package k2rule

import (
	"fmt"
	"os"
	"path/filepath"
)

// Config holds all K2Rule initialization settings.
// This is the unified configuration structure that replaces multiple Init* calls.
//
// Default behavior (all URLs auto-download from jsDelivr CDN):
//   - Empty RuleURL  → DefaultRuleURL (cn_blacklist.k2r.gz) unless IsGlobal=true
//   - Empty GeoIPURL → DefaultGeoIPURL (MaxMind GeoLite2)
//   - Empty PornURL  → DefaultPornURL (porn_domains.fst.gz)
//
// Priority: File paths take precedence over URLs
type Config struct {
	// Rule configuration
	RuleURL  string // Remote rule file URL ("" = use DefaultRuleURL, ignored if IsGlobal=true)
	RuleFile string // Local rule file path (takes precedence over RuleURL)

	// GeoIP configuration (always initialized with defaults)
	GeoIPURL  string // Remote GeoIP database URL ("" = use DefaultGeoIPURL)
	GeoIPFile string // Local .mmdb file path (takes precedence over GeoIPURL)

	// Porn detection (always initialized with defaults)
	PornURL  string // Remote porn database URL ("" = use DefaultPornURL)
	PornFile string // Local .fst.gz file path (takes precedence over PornURL)

	// Shared settings
	CacheDir string // Cache directory ("" = default ~/.cache/k2rule/)

	// Global proxy mode
	IsGlobal     bool   // true = global proxy mode, false = rule-based mode
	GlobalTarget Target // Target for global mode (default: TargetProxy)
}

// Validate checks for configuration conflicts.
// Returns an error if:
// - Both RuleURL and RuleFile are set
// - Both GeoIPURL and GeoIPFile are set
// - Both PornURL and PornFile are set
func (c *Config) Validate() error {
	if c.RuleURL != "" && c.RuleFile != "" {
		return fmt.Errorf("cannot specify both RuleURL and RuleFile")
	}
	if c.GeoIPURL != "" && c.GeoIPFile != "" {
		return fmt.Errorf("cannot specify both GeoIPURL and GeoIPFile")
	}
	if c.PornURL != "" && c.PornFile != "" {
		return fmt.Errorf("cannot specify both PornURL and PornFile")
	}
	return nil
}

// SetDefaults fills in default values for unset fields.
// - GlobalTarget defaults to TargetProxy
// - CacheDir defaults to ~/.cache/k2rule/
//
// Note: URL defaults are applied in Init(), not here:
// - Empty RuleURL  → DefaultRuleURL (unless IsGlobal=true)
// - Empty GeoIPURL → DefaultGeoIPURL
// - Empty PornURL  → DefaultPornURL
func (c *Config) SetDefaults() {
	if c.GlobalTarget == 0 {
		c.GlobalTarget = TargetProxy // Default global target
	}
	if c.CacheDir == "" {
		homeDir, _ := os.UserHomeDir()
		c.CacheDir = filepath.Join(homeDir, ".cache", "k2rule")
	}
}
