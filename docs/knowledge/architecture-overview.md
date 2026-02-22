# Architecture Overview

**Last Updated:** 2026-02-22
**Feature:** pure-go-rewrite

## Module

`github.com/kaitu-io/k2rule` — pure Go proxy routing library

## Top-Level API

Public surface lives at the root package `k2rule`:

| Symbol | Purpose |
|--------|---------|
| `Init(config)` | Initialize all components (rules, GeoIP, porn detection) |
| `Match(input)` | Route domain or IP → Target (DIRECT/PROXY/REJECT) |
| `IsPorn(domain)` | Porn domain detection |
| `ToggleGlobal(bool)` | Runtime toggle between rule-based and global proxy mode |
| `SetTmpRule(input, target)` | Per-connection override (highest priority) |
| `PornRemoteManager` | Auto-download + hot-reload of porn domain database |

## Internal Packages

```
internal/slice/
  format.go      — K2RULEV3 constants, SliceHeader (64B), SliceEntry (16B)
  writer.go      — SliceWriter: builds binary from domains/CIDRs/GeoIP
  reader.go      — SliceReader: heap-based queries (binary search domains)
  mmap_reader.go — MmapReader: zero-copy queries via edsrzf/mmap-go
  cached.go      — CachedMmapReader: lock-free hot-reload via atomic.Value

internal/clash/
  converter.go   — SliceConverter: Clash YAML → K2RULEV3 binary

internal/porn/
  heuristic.go   — IsPornHeuristic: 8 pattern layers, no I/O
  data.go        — Heuristic data (word lists, TLD patterns)
```

## Generator CLI

```
cmd/k2rule-gen/
  main.go        — CLI: generate-all, generate-porn subcommands
```

`generate-all`: reads `clash_rules/*.yml`, downloads rule-providers, converts via SliceConverter, gzip-writes `.k2r.gz`
`generate-porn`: fetches Bon-Appetit/porn-domains blocklist, filters heuristic domains, writes K2RULEV3 with target=Reject

## File Format: K2RULEV3

```
HEADER (64 bytes)
  Magic[8]           "K2RULEV3"
  Version[4]         uint32 LE = 1
  SliceCount[4]      uint32 LE
  FallbackTarget[1]  uint8
  Reserved[3]
  Timestamp[8]       int64 LE
  Checksum[16]       reserved (zeros)
  Reserved[16]

SLICE INDEX (16 bytes × SliceCount)
  SliceType[1]    0x01=SortedDomain, 0x02=CidrV4, 0x03=CidrV6, 0x04=GeoIP
  Target[1]       0=DIRECT, 1=PROXY, 2=REJECT
  Reserved[2]
  Offset[4]       uint32 LE — byte offset from file start to slice data
  Size[4]         uint32 LE — slice data size in bytes
  Count[4]        uint32 LE — number of entries in slice

SLICE DATA (variable, one region per slice)
  SortedDomain:
    count[4]          uint32 LE
    offsets[count+1]  uint32 LE each (sentinel = total strings length)
    strings_area      reversed, lowercased, dot-prefixed domains, concatenated
  CidrV4:   [network_BE(4) + prefix_len(1) + padding(3)] × count
  CidrV6:   [network(16) + prefix_len(1) + padding(7)] × count
  GeoIP:    [country_code(2) + padding(2)] × count
```

Distributed as `.k2r.gz` (gzip-compressed). `MmapReader` decompresses to a SHA256-named temp file and mmaps it.

## Targets

| Value | Constant | Meaning |
|-------|----------|---------|
| 0 | `TargetDirect` | Route directly |
| 1 | `TargetProxy` | Route via proxy |
| 2 | `TargetReject` | Block |

## Dependencies

| Package | Purpose |
|---------|---------|
| `github.com/edsrzf/mmap-go` | Cross-platform mmap |
| `github.com/oschwald/geoip2-golang` | MaxMind GeoIP2 reader |
| `gopkg.in/yaml.v3` | Clash YAML config parsing |

Domain matching, binary search, gzip, HTTP downloads: stdlib only.

## Match Priority Order

1. LAN/Private IPs → DIRECT (hardcoded)
2. TmpRule exact match (SetTmpRule)
3. Global mode → GlobalTarget (if IsGlobal=true)
4. IP-CIDR rule matching
5. GeoIP rule matching
6. Domain rule matching
7. Fallback from rule file header
