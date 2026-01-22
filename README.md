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
k2rule-gen convert -i clash_rules/cn_blacklist.yml -o cn_blacklist.bin
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

## Automatic Updates

This repository uses GitHub Actions to automatically update rules daily at 7:00 AM Beijing time (23:00 UTC). The workflow downloads the latest rules from [Loyalsoldier/clash-rules](https://github.com/Loyalsoldier/clash-rules) and generates binary files.

## License

MIT
