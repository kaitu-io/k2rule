# k2rule — Developer Reference

Pure Go proxy routing library. Reads K2RULEV3 binary rule files, matches domain/IP/GeoIP traffic, and provides porn domain detection. No Rust. No cross-language dependencies.

## Module

`github.com/kaitu-io/k2rule` · Go 1.21+

## Directory Structure

```
k2rule/
├── *.go                    # Public API (matcher, config, porn, remote, target, retry)
├── cmd/
│   └── k2rule-gen/
│       └── main.go         # CLI: generate-all, generate-porn subcommands
├── internal/
│   ├── slice/
│   │   ├── format.go       # K2RULEV3 constants, SliceHeader (64B), SliceEntry (16B)
│   │   ├── writer.go       # SliceWriter — builds K2RULEV3 binary
│   │   ├── reader.go       # SliceReader — heap-based queries
│   │   ├── mmap_reader.go  # MmapReader — zero-copy queries via mmap
│   │   └── cached.go       # CachedMmapReader — lock-free hot-reload
│   ├── clash/
│   │   └── converter.go    # SliceConverter: Clash YAML → K2RULEV3
│   ├── porn/
│   │   ├── heuristic.go    # IsPornHeuristic: 8-layer pattern matching
│   │   └── data.go         # Heuristic data (word lists, TLD patterns)
│   ├── cache/              # Internal cache utilities
│   └── geoip/              # GeoIP helpers
├── clash_rules/            # Clash YAML source configs (cn_blacklist.yml, cn_whitelist.yml)
├── docs/
│   ├── features/           # Feature specs (pure-go-rewrite.md, etc.)
│   ├── knowledge/          # Distilled patterns (architecture, bugs, testing)
│   └── *.md                # Architecture docs
├── examples/basic/         # Usage example
└── .github/workflows/
    └── generate-rules.yml  # CI: go test + generate-all + generate-porn + release
```

## Key Modules

### `internal/slice` — Format + I/O

The core binary format layer. All three reader types share the same K2RULEV3 format.

| Type | Use |
|------|-----|
| `SliceWriter` | Build K2RULEV3 binary (used by generator and converter) |
| `SliceReader` | In-memory queries (used for porn checker) |
| `MmapReader` | Zero-copy queries — decompresses gzip to temp file, then mmaps |
| `CachedMmapReader` | Lock-free hot-reload using `atomic.Value` |

### `internal/clash` — Clash YAML Converter

`SliceConverter.Convert(yaml)` → K2RULEV3 binary bytes.

- Handles: `DOMAIN`, `DOMAIN-SUFFIX`, `IP-CIDR`, `IP-CIDR6`, `GEOIP`, `RULE-SET`, `MATCH`
- `GEOIP,LAN` expands to private IPv4/IPv6 CIDRs (not a country lookup)
- Adjacent same-type same-target slices are merged before writing
- `SetProviderRules(name, rules)` / `LoadProvider(name, content)` inject provider rules (bypasses HTTP in tests)

### `internal/porn` — Heuristic Detection

`IsPornHeuristic(domain)` — stateless, 8-layer pattern matching. No I/O. Used as the fast first pass before K2RULEV3 lookup.

### Root Package — Public API

| Function | Description |
|----------|-------------|
| `Init(config)` | Initialize all components |
| `Match(input)` | Route domain or IP string → Target |
| `IsPorn(domain)` | Porn detection (heuristic + K2RULEV3) |
| `ToggleGlobal(bool)` | Switch global proxy mode at runtime |
| `SetTmpRule(input, target)` | Per-connection rule override |

## File Format: K2RULEV3

Magic: `"K2RULEV3"` (8 bytes). Header 64 bytes, little-endian throughout.

```
HEADER (64B): Magic[8] + Version[4] + SliceCount[4] + FallbackTarget[1] + Reserved[3] + Timestamp[8] + Checksum[16] + Reserved[16]
SLICE INDEX (16B × N): SliceType[1] + Target[1] + Reserved[2] + Offset[4] + Size[4] + Count[4]
SLICE DATA (variable):
  SortedDomain: count[4] + offsets[count+1][4 each] + strings_area
  CidrV4: [network_BE(4) + prefix_len(1) + padding(3)] × count
  CidrV6: [network(16) + prefix_len(1) + padding(7)] × count
  GeoIP:  [country_code(2) + padding(2)] × count
```

Domain encoding: lowercase → dot-prefix → reverse → sort → dedup.
`"google.com"` → `".google.com"` → `"moc.elgoog."`

Distributed as `.k2r.gz`. `MmapReader` decompresses to a SHA256-named temp file first.

## Targets

| Value | Constant | Meaning |
|-------|----------|---------|
| 0 | `TargetDirect` | Route directly |
| 1 | `TargetProxy` | Route via proxy |
| 2 | `TargetReject` | Block |

## Match Priority

1. LAN/private IP → DIRECT (hardcoded)
2. TmpRule exact match
3. Global mode → GlobalTarget
4. IP-CIDR rules
5. GeoIP rules
6. Domain rules
7. Fallback from file header

## Generator CLI

```bash
go run ./cmd/k2rule-gen generate-all -o output/ -v
go run ./cmd/k2rule-gen generate-porn -o output/porn_domains.k2r.gz -v
```

`generate-all`: reads `clash_rules/*.yml`, downloads rule-providers via HTTP, converts, gzip-writes.
`generate-porn`: fetches Bon-Appetit/porn-domains blocklist, filters heuristic-detectable domains, writes K2RULEV3 with target=Reject.

## CI/CD

`.github/workflows/generate-rules.yml` — runs on push to master and daily schedule:
1. `go test ./...`
2. `go run ./cmd/k2rule-gen generate-all -o output/ -v`
3. `go run ./cmd/k2rule-gen generate-porn -o output/porn_domains.k2r.gz -v`
4. Creates GitHub Release + deploys to `release` branch

## Config

`CacheDir` is **required** — `Init()` returns an error if empty.

```go
k2rule.Init(&k2rule.Config{
    CacheDir: "/path/to/cache",  // required
    RuleURL:  "",                // "" = DefaultRuleURL
    PornURL:  "",                // "" = DefaultPornURL
    GeoIPURL: "",                // "" = DefaultGeoIPURL
})
```

## Dependencies

| Package | Purpose |
|---------|---------|
| `github.com/edsrzf/mmap-go` | Cross-platform mmap |
| `github.com/oschwald/geoip2-golang` | MaxMind GeoIP2 |
| `gopkg.in/yaml.v3` | Clash YAML parsing |

## Domain Vocabulary

| Term | Definition |
|------|------------|
| K2RULEV3 | Current binary format (sorted bytes, binary search) |
| K2RULEV2 | Previous format (FST-based, Rust writer) — deleted |
| SliceWriter | Go type that builds K2RULEV3 binary |
| SliceReader | Heap-based K2RULEV3 reader |
| MmapReader | Zero-copy K2RULEV3 reader via mmap |
| CachedMmapReader | Atomic hot-reload wrapper for MmapReader |
| SliceConverter | Clash YAML → K2RULEV3 converter |
| PORNFST | Previous porn format — deleted, replaced by K2RULEV3 |
| SortedDomain | K2RULEV3 slice type 0x01 — reversed, sorted domain bytes |
| Fallback | Default target when no rule matches (stored in file header) |
| TmpRule | Runtime per-connection rule override (sync.Map, highest priority) |
| generate-all | CLI subcommand: Clash YAML → K2RULEV3 files |
| generate-porn | CLI subcommand: blocklist → porn K2RULEV3 file |
| IsPornHeuristic | Stateless 8-layer porn domain pattern matcher |

## Knowledge Base

`docs/knowledge/` — distilled patterns from implementation:

- `architecture-decisions.md` — why K2RULEV3, mmap + temp file, atomic hot-reload, etc.
- `architecture-overview.md` — module map, format spec, match priority
- `bugfix-patterns.md` — cross-language drift, suffix false positives, URL parsing
- `testing-strategies.md` — writer-first TDD, shared helpers, HTTP bypass via SetProviderRules
- `framework-gotchas.md` — mmap + gzip, sort.Search semantics, binary.Read unexported fields
