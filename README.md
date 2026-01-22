# k2rule

A high-performance rule-based routing/filtering system written in Rust, with binary index format for efficient rule matching.

## Features

- **High Performance**: Binary index format with O(log n) or O(1) lookups
- **Memory Efficient**: Memory-mapped file support for large rule sets
- **Cross-Platform**: Works on macOS, Linux, Windows, and mobile via FFI
- **Clash Compatible**: Convert Clash YAML rules to binary format

## Rule Types

- **DOMAIN**: Domain name matching (exact and suffix)
- **IP-CIDR**: IPv4/IPv6 CIDR range matching
- **GEOIP**: Geographic IP-based routing
- **IP-MATCH**: Exact IP address matching

## Binary Format

The binary format uses a `header + index + payload` structure:

```
+------------------+
|     HEADER       |  128 bytes (fixed)
+------------------+
|   DOMAIN INDEX   |  variable
+------------------+
|    CIDR INDEX    |  variable
+------------------+
|   GEOIP INDEX    |  variable
+------------------+
|     IP INDEX     |  variable
+------------------+
|     PAYLOAD      |  variable
+------------------+
```

## Installation

```bash
cargo install --path .
```

## CLI Usage

### Convert Clash YAML to Binary

```bash
k2rule-gen convert -i clash_rules/cn_blacklist.yml -o cn_blacklist.k2r
```

### Generate All Rule Sets

```bash
k2rule-gen generate-all -o output/
```

### Download and Generate from Remote

```bash
k2rule-gen download -o output/ -v
```

## Library Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
k2rule = { git = "https://github.com/kaitu-io/k2rule" }
```

Example:

```rust
use k2rule::{match_rule, add_direct_domain, Target};

// Initialize and match
let target = match_rule("www.google.com");
assert_eq!(target, Target::Proxy);

// Add dynamic rules
add_direct_domain(&["example.com"]);
```

## Remote Rule Management

For applications that need to download and cache rules from a remote server, use `RemoteRuleManager`:

```rust
use k2rule::{RemoteRuleManager, Target};
use std::path::Path;

// Create manager with remote URL and local cache directory
let mut manager = RemoteRuleManager::new(
    "https://cdn.jsdelivr.net/gh/kaitu-io/k2rule@release/cn_blacklist.k2r.gz",
    Path::new("/tmp/k2rule-cache"),
    Target::Direct, // fallback when no rule matches
);

// Initialize: loads from cache or downloads if needed
manager.init()?;

// Query rules
let target = manager.match_domain("google.com");
let target = manager.match_ip("8.8.8.8".parse().unwrap());

// Check for updates (uses ETag for efficiency)
if manager.update()? {
    println!("Rules updated and hot-reloaded!");
}
```

### Features

- **Gzip compression**: Rule files can be served as `.k2r.gz` for bandwidth efficiency
- **ETag support**: Conditional requests avoid unnecessary downloads (304 Not Modified)
- **Atomic updates**: Cache files are updated atomically to prevent corruption
- **Hot reload**: Rules are reloaded without restarting the application
- **LRU caching**: Frequently matched domains/IPs are cached for faster lookups

### Custom Configuration

For advanced use cases, configure the LRU cache size:

```rust
use k2rule::{RemoteRuleManager, CachedReaderConfig, Target};

let config = CachedReaderConfig::with_capacity(2000); // 2000 entries per cache
let manager = RemoteRuleManager::with_config(
    "https://cdn.jsdelivr.net/gh/kaitu-io/k2rule@release/cn_blacklist.k2r.gz",
    Path::new("/tmp/cache"),
    Target::Direct,
    config,
);
```

### Pre-built Rules

Pre-built binary rule files are available via jsDelivr CDN:

| Rule Set | Description | URL |
|----------|-------------|-----|
| `cn_blacklist.k2r.gz` | Blacklist mode: specific sites use proxy, fallback to direct | `https://cdn.jsdelivr.net/gh/kaitu-io/k2rule@release/cn_blacklist.k2r.gz` |
| `cn_whitelist.k2r.gz` | Whitelist mode: most traffic direct, GFW blocked sites use proxy | `https://cdn.jsdelivr.net/gh/kaitu-io/k2rule@release/cn_whitelist.k2r.gz` |

Rules are updated daily from [Loyalsoldier/clash-rules](https://github.com/Loyalsoldier/clash-rules).

Source rule files (Clash YAML format) via jsDelivr:
- `https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/direct.txt`
- `https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/proxy.txt`
- `https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/reject.txt`

## Automatic Updates

This repository uses GitHub Actions to automatically update rules daily at 7:00 AM Beijing time (23:00 UTC). The workflow downloads the latest rules from [Loyalsoldier/clash-rules](https://github.com/Loyalsoldier/clash-rules) and generates binary files.

## License

MIT
