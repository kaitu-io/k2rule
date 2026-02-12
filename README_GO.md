# K2Rule Go SDK

High-performance rule engine for VPN/proxy traffic routing and content filtering, with **memory-mapped architecture** for minimal memory footprint and **unified config-based API**.

## 🚀 Features

- ✅ **Unified Config API**: Single `Init(config)` for all initialization - no repeated parameters
- ✅ **Global Proxy Mode**: Toggle between VPN-style全局代理 and rule-based routing at runtime
- ✅ **LAN IP Bypass**: Automatic detection of private/LAN IPs (always DIRECT)
- ✅ **Out-of-the-box**: Auto-download rules from CDN, no manual setup
- ✅ **Memory-efficient**: Uses memory-mapped files (~200 KB resident memory vs 5-10 MB with full loading)
- ✅ **Hot-reload**: Seamless rule updates without service interruption
- ✅ **Auto-update**: Background checks every 6 hours with ETag optimization
- ✅ **Cross-platform**: Linux, macOS, Windows, iOS, Android support

## Installation

```bash
go get github.com/kaitu-io/k2rule
```

## 🎯 Quick Start - Config-Based API (v1.0.0+)

### Single Init Call

```go
package main

import "github.com/kaitu-io/k2rule"

func main() {
    // One-time initialization with all settings
    config := &k2rule.Config{
        RuleURL:  "https://cdn.jsdelivr.net/gh/kaitu-io/k2rule@release/cn_blacklist.k2r.gz",
        GeoIPURL: "",  // Use default MaxMind GeoLite2
        PornURL:  "",  // Use default porn database
        CacheDir: "",  // Use default ~/.cache/k2rule/
    }

    k2rule.Init(config)

    // All matching automatically handles LAN bypass
    target := k2rule.Match("google.com")    // → Rules
    target = k2rule.Match("192.168.1.1")    // → DIRECT (LAN bypass)
    target = k2rule.Match("8.8.8.8")        // → Rules + GeoIP
}
```

### Global Proxy Mode

```go
// Enable global proxy mode (VPN-style全局代理)
config := &k2rule.Config{
    IsGlobal:     true,
    GlobalTarget: k2rule.TargetProxy,
}
k2rule.Init(config)

// All traffic → PROXY (except LAN)
k2rule.Match("google.com")   // → PROXY
k2rule.Match("192.168.1.1")  // → DIRECT (LAN bypass)

// Runtime toggle
k2rule.ToggleGlobal(false)   // Switch to rule-based mode
k2rule.ToggleGlobal(true)    // Back to global mode
```

### Pure Global Mode (No Rules)

```go
// VPN without any rule files
config := &k2rule.Config{
    IsGlobal:     true,
    GlobalTarget: k2rule.TargetProxy,
}
k2rule.Init(config)

// Everything goes to proxy except LAN
k2rule.Match("anything.com")  // → PROXY
k2rule.Match("10.0.0.1")      // → DIRECT (LAN)
```

## 🌐 CDN Rule Resources

**Pre-built rule files:**
```
https://cdn.jsdelivr.net/gh/kaitu-io/k2rule@release/cn_blacklist.k2r.gz
https://cdn.jsdelivr.net/gh/kaitu-io/k2rule@release/cn_whitelist.k2r.gz
https://cdn.jsdelivr.net/gh/kaitu-io/k2rule@release/porn_domains.fst.gz
```

**Update frequency:** Daily auto-update (source: [Loyalsoldier/clash-rules](https://github.com/Loyalsoldier/clash-rules))

**Cache mechanism:**
- First run: Auto-download to `~/.cache/k2rule/`
- Subsequent runs: Use cache (5-10ms startup)
- Auto-update: Background checks every 6 hours (ETag-based, 304 skips download)

## 📖 API Reference

### Configuration

```go
type Config struct {
    // Rule configuration (choose one or none for pure global mode)
    RuleURL  string  // Remote rule file URL
    RuleFile string  // Local rule file path

    // GeoIP configuration (optional)
    GeoIPURL  string  // "" = default MaxMind GeoLite2, non-empty = custom
    GeoIPFile string  // Local .mmdb file path

    // Porn detection (optional)
    PornURL  string  // "" = default CDN, non-empty = custom
    PornFile string  // Local .fst.gz file path

    // Shared settings
    CacheDir string  // "" = default ~/.cache/k2rule/, shared by all components

    // Global proxy mode
    IsGlobal     bool   // true = global proxy mode, false = rule-based mode
    GlobalTarget Target // Target for global mode (default: TargetProxy)
}
```

### Initialization

```go
// Init initializes K2Rule with unified configuration
// This is the ONLY way to initialize K2Rule in v1.0.0+
func Init(config *Config) error

// Runtime configuration updates
func ToggleGlobal(enabled bool)        // Switch global mode on/off
func SetGlobalTarget(target Target)    // Change global target
func GetConfig() Config                 // Get current config (copy)
func UpdateConfig(config *Config) error // Hot-reload config
```

### Matching

```go
// Match automatically detects input type and returns routing target
// Priority:
//   1. LAN/Private IPs → DIRECT (always)
//   2. Global mode → GlobalTarget
//   3. Rules → Domain/IP-CIDR/GeoIP rules
//   4. Fallback → Rule file fallback or GlobalTarget
func Match(input string) Target
```

### Helpers

```go
// IsPrivateIP checks if an IP is in a private/LAN range
func IsPrivateIP(ip string) bool

// IsPorn checks if domain is porn (heuristic + FST if initialized)
func IsPorn(domain string) bool

// IsPornHeuristic checks using heuristic only (no FST needed)
func IsPornHeuristic(domain string) bool
```

### Targets

```go
type Target uint8

const (
    TargetDirect Target = 0  // Direct connection
    TargetProxy  Target = 1  // Proxy connection
    TargetReject Target = 2  // Reject/block
)
```

## 🔧 Configuration Examples

### Full Configuration

```go
config := &k2rule.Config{
    RuleURL:      "https://cdn.../cn_blacklist.k2r.gz",
    GeoIPURL:     "",  // Use default MaxMind GeoLite2
    PornURL:      "",  // Use default porn database
    CacheDir:     "",  // Use default ~/.cache/k2rule/
    IsGlobal:     false,
    GlobalTarget: k2rule.TargetProxy,
}

k2rule.Init(config)
```

### Local Files Only

```go
config := &k2rule.Config{
    RuleFile:  "./rules/cn_blacklist.k2r.gz",
    GeoIPFile: "./GeoLite2-Country.mmdb",
    PornFile:  "./porn_domains.fst.gz",
    CacheDir:  "./cache",
}

k2rule.Init(config)
```

### iOS App Configuration

```go
import "path/filepath"

// Get app's Library/Caches directory
documentsURL, _ := os.UserConfigDir()
cacheDir := filepath.Join(documentsURL, "..", "Library", "Caches", "k2rule")

config := &k2rule.Config{
    RuleURL:  "https://cdn.../cn_blacklist.k2r.gz",
    CacheDir: cacheDir,  // iOS sandbox-safe location
}

k2rule.Init(config)
```

### Rules-Only (No GeoIP or Porn Detection)

```go
config := &k2rule.Config{
    RuleURL: "https://cdn.../cn_blacklist.k2r.gz",
}

k2rule.Init(config)
```

## 🔒 LAN IP Bypass (Hardcoded)

All private/LAN IPs automatically return DIRECT, regardless of rules or global mode:

**IPv4 Private Ranges:**
- `10.0.0.0/8` - Private network
- `172.16.0.0/12` - Private network
- `192.168.0.0/16` - Private network
- `127.0.0.0/8` - Loopback
- `169.254.0.0/16` - Link-local

**IPv6 Private Ranges:**
- `::1/128` - Loopback
- `fe80::/10` - Link-local
- `fc00::/7` - Unique local addresses

**Example:**
```go
k2rule.Match("192.168.1.1")  // → DIRECT (always)
k2rule.Match("10.0.0.1")     // → DIRECT (always)
k2rule.Match("::1")          // → DIRECT (always)

// Even in global mode, LAN IPs go DIRECT
config := &k2rule.Config{IsGlobal: true, GlobalTarget: k2rule.TargetProxy}
k2rule.Init(config)
k2rule.Match("192.168.1.1")  // → DIRECT (LAN bypass)
```

**Helper function:**
```go
if k2rule.IsPrivateIP("192.168.1.1") {
    // Always true for LAN IPs
}
```

## 🌍 Global Rules (Fallback)

In K2Rule, "global rules" refer to the fallback behavior when no rules match:

### In Clash YAML

The last `MATCH` rule becomes the fallback:

```yaml
rules:
  - DOMAIN-SUFFIX,google.com,PROXY
  - GEOIP,CN,DIRECT
  - MATCH,DIRECT    # ← This is the fallback/global rule
```

When compiled to `.k2r`, this `MATCH,DIRECT` is stored in the file header as the fallback target.

### In Go SDK

- **With rules**: Fallback is read from `.k2r` file header
- **Without rules (pure global mode)**: Uses `Config.GlobalTarget`

```go
// Rules loaded → fallback from file
config := &k2rule.Config{
    RuleURL: "https://.../cn_blacklist.k2r.gz",
}
k2rule.Init(config)
k2rule.Match("unmatched.com")  // → DIRECT (from k2r file's MATCH rule)

// No rules → use GlobalTarget
config := &k2rule.Config{
    IsGlobal:     true,
    GlobalTarget: k2rule.TargetProxy,
}
k2rule.Init(config)
k2rule.Match("anything.com")  // → PROXY (from GlobalTarget)
```

## 🔄 Runtime Configuration

### Toggle Global Mode

```go
// Start in rule-based mode
config := &k2rule.Config{
    RuleURL:  "https://.../rules.k2r.gz",
    IsGlobal: false,
}
k2rule.Init(config)

k2rule.Match("google.com")  // → Check rules

// Switch to global mode (all traffic → proxy)
k2rule.ToggleGlobal(true)
k2rule.Match("google.com")  // → PROXY (global mode)
k2rule.Match("10.0.0.1")    // → DIRECT (LAN bypass)

// Switch back
k2rule.ToggleGlobal(false)
k2rule.Match("google.com")  // → Check rules again
```

### Change Global Target

```go
k2rule.SetGlobalTarget(k2rule.TargetReject)  // Block all in global mode
k2rule.ToggleGlobal(true)
k2rule.Match("anything.com")  // → REJECT
```

### Get Current Config

```go
config := k2rule.GetConfig()
fmt.Printf("Global mode: %v\n", config.IsGlobal)
fmt.Printf("Cache dir: %s\n", config.CacheDir)
```

### Hot-Reload Config

```go
newConfig := &k2rule.Config{
    RuleURL:  "https://new-rules.k2r.gz",
    IsGlobal: false,
}
k2rule.UpdateConfig(newConfig)  // Re-initializes all components
```

## 🧪 Porn Detection

```go
// Initialize with porn detection
config := &k2rule.Config{
    RuleURL: "https://.../cn_blacklist.k2r.gz",
    PornURL: "",  // Use default CDN
}
k2rule.Init(config)

// Check domains
if k2rule.IsPorn("pornhub.com") {
    // Block access
}

// Heuristic-only check (no FST needed, faster)
if k2rule.IsPornHeuristic("example.xxx") {
    // Quick porn check
}
```

## 📊 Performance

**Memory Usage:**
- Rules: ~200 KB (mmap'd, shared across processes)
- GeoIP database: ~10 MB (mmap'd, shared)
- Porn FST: ~2.6 MB (mmap'd)
- **Total**: ~12.8 MB resident memory

**Matching Speed:**
- Domain matching: ~500 ns/op (0 allocations)
- IP-CIDR matching: ~1 μs/op (0 allocations)
- IP + GeoIP matching: ~10-20 μs/op
- Porn heuristic: ~17 μs/op
- Porn FST: ~25 μs/op

## 🔄 Migration from v0.4.0 to v1.0.0

### Breaking Changes

**Old API (v0.4.0) - REMOVED:**
```go
// ❌ These functions no longer exist in v1.0.0
k2rule.InitRemote("https://.../rules.k2r.gz", "")
k2rule.InitFromFile("./rules.k2r.gz")
k2rule.InitGeoIP("", "")
k2rule.InitPorn()
k2rule.InitPornRemote("", "")
```

**New API (v1.0.0) - ONE INIT METHOD:**
```go
// ✅ Unified config-based initialization
k2rule.Init(&k2rule.Config{
    RuleURL:  "https://.../rules.k2r.gz",
    GeoIPURL: "",
    PornURL:  "",
})
```

### Migration Examples

**Before (v0.4.0):**
```go
// Multiple Init calls with repeated parameters
k2rule.InitRemote("https://.../cn_blacklist.k2r.gz", "")
k2rule.InitGeoIP("", "")      // Repeated cacheDir parameter
k2rule.InitPorn()             // Using default

target := k2rule.Match("google.com")
```

**After (v1.0.0):**
```go
// Single Init call, all configuration in one place
config := &k2rule.Config{
    RuleURL:  "https://.../cn_blacklist.k2r.gz",
    GeoIPURL: "",  // Shared cacheDir, no repetition
    PornURL:  "",
}
k2rule.Init(config)

target := k2rule.Match("google.com")
```

### New Features in v1.0.0

- ✨ Unified Config-based initialization
- ✨ Global proxy mode support (IsGlobal)
- ✨ Automatic LAN IP bypass (hardcoded)
- ✨ Runtime configuration APIs (ToggleGlobal, SetGlobalTarget, GetConfig, UpdateConfig)
- ✨ Pure global mode (no rules required)

## 📝 License

MIT License
