# Architecture Decisions

## AD-001: K2RULEV3 — Sorted Bytes + Binary Search Replaces FST

**Feature:** pure-go-rewrite
**Date:** 2026-02-22
**Status:** implemented

### Decision

Replace the FST (Finite State Transducer) domain encoding from K2RULEV2 with a flat, sorted-bytes layout using standard library binary search.

### Context

K2RULEV2 stored domain slices in the Rust `fst` crate's binary format. The Go FST reader was ~220 lines of fragile cross-language parsing code tightly coupled to a specific fst crate version, causing `invalid magic` and `unsupported FST version` runtime errors.

### The Format (K2RULEV3 Domain Slice)

```
count      (4 bytes LE)  number of domains
offsets[0] (4 bytes LE)  byte offset into strings area
...
offsets[count-1]
sentinel   (4 bytes LE)  total strings length
strings area (variable)  reversed, lowercased, dot-prefixed domains, sorted
```

Domain normalization: `"google.com"` → `".google.com"` → `"moc.elgoog."` (lowercase, dot-prefix, reverse). Sorting after reversal groups all subdomains of the same TLD together, enabling efficient suffix matching.

### Query Algorithm

For `"www.youtube.com"`:
1. Lowercase: `"www.youtube.com"`
2. Generate suffixes: `[".www.youtube.com", ".youtube.com", ".com"]`
3. Reverse each: `["moc.ebutuoy.www.", "moc.ebutuoy.", "moc."]`
4. Binary search each in sorted strings area
5. First match wins

### Trade-offs

- Space: ~240KB uncompressed for 10K domains vs ~180KB FST. Gzip-compressed the difference shrinks to ~20KB. Acceptable.
- Speed: log2(10000) ≈ 14 comparisons per suffix, each ~20 bytes. Total < 1μs per query.
- Complexity: ~50 lines of Go vs ~220 lines of cross-language FST reader.
- Same-language writer/reader eliminates format version drift permanently.

### Validating Tests

- `TestSortedDomainBinarySearch` — `internal/slice/reader_test.go`
- `TestDomainSuffixMatching` — `internal/slice/reader_test.go`
- `TestDomainOrderingPreserved` — `internal/slice/reader_test.go`
- `TestDomainCaseInsensitive` — `internal/slice/reader_test.go`
- `TestDomainNormalization` — `internal/slice/writer_test.go`
- `TestSliceWriterMultipleDomains` — `internal/slice/writer_test.go`
- `TestSliceWriterDomainAlreadyDotPrefixed` — `internal/slice/writer_test.go`

---

## AD-002: mmap + Decompressed Temp File for Zero-Copy Reads

**Feature:** pure-go-rewrite
**Date:** 2026-02-22
**Status:** implemented

### Decision

`MmapReader` decompresses `.k2r.gz` to a SHA256-named temp file, then mmaps the uncompressed file. The temp file name is deterministic (first 16 hex chars of SHA256 of the gzip path) so repeated calls reuse the decompressed file without re-decompressing.

### Context

mmap requires a real file descriptor. Gzip streams cannot be mmap'd directly. Options were: decompress to memory (no zero-copy benefit) or decompress to temp file (preserves zero-copy).

### Implementation

```go
hash, _ := computeFileSHA256(gzipPath)
tmpPath := filepath.Join(filepath.Dir(gzipPath), fmt.Sprintf("k2rule-%s.bin", hash))
if _, err := os.Stat(tmpPath); err == nil {
    return NewMmapReader(tmpPath) // cache hit
}
decompressGzip(gzipPath, tmpPath)
return NewMmapReader(tmpPath)
```

### Trade-off

Doubles disk usage (gzip + decompressed), but decompressed files are ~240KB for typical rule sets. Acceptable. No heap allocation per domain query on the hot path.

### Validating Tests

- `TestMmapSortedDomainMatch` — `internal/slice/reader_test.go`
- `TestMmapReaderFromGzipV3` — `internal/slice/reader_test.go`

---

## AD-003: Porn Domains Unified into K2RULEV3 (PORNFST Deleted)

**Feature:** pure-go-rewrite
**Date:** 2026-02-22
**Status:** implemented

### Decision

Delete the `PORNFST` format entirely. Porn domain lists are stored as standard K2RULEV3 files (`porn_domains.k2r.gz`) with a single domain slice and `target = Reject (2)`.

### Context

Maintaining two binary formats (K2RULEV3 for rules, PORNFST for porn) doubles the reader code surface. The porn list is structurally identical to any domain blocklist.

### Detection Flow

```
IsPorn(domain)
  → porn.IsPornHeuristic(domain)   // 8 heuristic layers, no I/O
  → reader.MatchDomain(domain)     // K2RULEV3 binary search
      → if *target == 2 (Reject): return true
```

### Heuristic Filter in Generator

`generate-porn` filters out heuristic-detectable domains before writing to the K2RULEV3 file. This keeps the binary smaller and avoids redundancy.

### Validating Tests

- `TestPornCheckerWithSliceReader` — `porn_test.go`
- `TestPornRemoteManagerK2R` — `porn_remote_test.go`

---

## AD-004: Go CLI Generator Replaces Rust k2rule-gen

**Feature:** pure-go-rewrite
**Date:** 2026-02-22
**Status:** implemented

### Decision

Delete the Rust `k2rule-gen` binary and replace with `cmd/k2rule-gen` in Go. The Go generator uses the same `SliceWriter` as the reader library, making format version drift impossible by construction.

### Two Subcommands

- `generate-all`: reads `clash_rules/*.yml`, downloads rule-providers via HTTP, converts via `SliceConverter`, gzip-writes `.k2r.gz` files
- `generate-porn`: fetches Bon-Appetit/porn-domains `meta.json`, downloads blocklist, filters heuristic domains, builds K2RULEV3 with `target=Reject`

### No External CLI Dependencies

Uses only `flag` (stdlib) for argument parsing. No cobra, urfave/cli, etc.

### Validating Tests

- `TestGoGeneratorBuilds` — `ci_check_test.go`
- `TestGenerateAllFromClashYAML` — `cmd/k2rule-gen/main_test.go`
- `TestGeneratePornDomains` — `cmd/k2rule-gen/main_test.go`

---

## AD-005: CachedMmapReader Uses atomic.Value for Lock-Free Hot-Reload

**Feature:** pure-go-rewrite
**Date:** 2026-02-22
**Status:** implemented

### Decision

`CachedMmapReader` wraps `atomic.Value` to provide lock-free concurrent read access with atomic swap on reload. Old readers are closed in a goroutine after a 5-second grace period to allow in-flight reads to complete without a mutex.

### Why Not sync.RWMutex

A read lock would block all readers during the brief window of a reload. For a proxy library called from many goroutines, lock-free is preferable. The 5-second grace period is conservative; typical domain lookups complete in microseconds.

### Validating Tests

- `TestCachedMmapReaderAtomicSwap` — `internal/slice/cached_test.go` (if present) / covered by integration tests

---

## AD-006: Runtime Memory Optimization — mmap for Porn + Zero-Alloc GeoIP

**Date:** 2026-03-03
**Status:** implemented

### Decision

Two optimizations to minimize runtime heap memory:

1. **PornChecker: SliceReader → CachedMmapReader** — porn rule data moved from Go heap to file-backed mmap
2. **GeoIP: maxminddb direct + minimal struct + offset cache** — replaced geoip2-golang wrapper with direct maxminddb usage, eliminating ~50 allocs/2.5KB per lookup

### Context — Before

| Component | Heap | mmap |
|-----------|------|------|
| Rules (CachedMmapReader) | ~600 B | ~6-11 MB |
| PornChecker (SliceReader) | **5-25 MB** | 0 |
| GeoIP (geoip2.Country) | **~2.5 KB/lookup** | 9.19 MB |
| **Total steady-state heap** | **5-25 MB** | |

PornChecker used `SliceReader` which calls `os.ReadFile` + `io.ReadAll`, loading the entire decompressed K2RULEV3 file into Go heap. During hot-reload, three copies coexisted briefly (old data + new compressed + new decompressed = 3-5x the file size).

GeoIP used `geoip2.Country()` which decoded the full struct (3 Names maps with 8 languages, Continent, RegisteredCountry, RepresentedCountry, Traits) but k2rule only used `Country.IsoCode` (2 bytes).

### Context — After

| Component | Heap | mmap |
|-----------|------|------|
| Rules (CachedMmapReader) | ~600 B | ~6-11 MB |
| PornChecker (CachedMmapReader) | ~600 B | ~5-10 MB |
| GeoIP (maxminddb + offset cache) | ~2.5 KB total | 9.19 MB (RSS ~300 KB) |
| **Total steady-state heap** | **~54 KB** | |

### GeoIP Optimization Details

Uses `maxminddb.Reader.LookupOffset(ip)` for zero-alloc trie traversal, then caches offset→country code in `sync.Map`. GeoLite2-Country has ~250 unique country records (normalized DB), so cache is bounded at ~250 entries. After warmup, all lookups hit cache = zero heap allocations.

`countryRecord` minimal struct only decodes `country.iso_code`, skipping Names/Continent/RegisteredCountry/Traits fields (~50 allocs → ~5 allocs per first-time decode).

Dependency changed from `geoip2-golang` (wrapper) to `maxminddb-golang` (direct) — removes one dependency.

### PornChecker Optimization Details

Changed `PornChecker.reader` from `*slice.SliceReader` to `*slice.CachedMmapReader`. Same pattern as `RemoteRuleManager` — lock-free `atomic.Value` swap with 5-second grace period.

`PornRemoteManager` simplified: removed `checker *PornChecker` + `sync.RWMutex`, replaced with `reader *slice.CachedMmapReader` directly. `loadDatabase` reduced to one line: `m.reader.Load(path)`.

### All mmap is file-backed and evictable

All mmap regions use `MAP_SHARED` + `PROT_READ`. The OS can reclaim any page under memory pressure without writeback. Pages are not counted toward Go heap and are not scanned by GC.

### Validating Tests

- `TestPornCheckerWithSliceReader` — `porn_test.go` (now uses CachedMmapReader internally)
- `TestPornCheckerFromFile` — `porn_test.go`
- `TestPornRemoteManager_IsPorn_NotInitialized` — `porn_remote_test.go`
- `TestGeoIPManager_Init` — `geoip_manager_test.go`
- `TestGeoIPManager_LookupCountry_NotInitialized` — `geoip_manager_test.go`
