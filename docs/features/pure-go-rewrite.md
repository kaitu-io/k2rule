# Pure Go Rewrite: Eliminate Rust, Unified K2RULEV3

**Status:** draft
**Version:** 1.0
**Created:** 2026-02-22

## Summary

Delete all Rust code. Rewrite the binary rule file generator in Go. Upgrade the file format from K2RULEV2 (FST-based) to K2RULEV3 (sorted bytes + binary search). Unify porn domain storage into the same format. All generation and reading happens in Go — no cross-language dependencies.

## Motivation

- K2RULEV2 uses Rust `fst` crate's binary format for domain storage. The Go FST reader is buggy and tightly coupled to a specific `fst` crate version — this is the root cause of the current `invalid magic` / `unsupported FST version` errors.
- Maintaining two languages (Rust writer + Go reader) creates version drift problems that are hard to test across language boundaries.
- The FST format's complexity (~220 lines Go reader) provides diminishing returns: for ~10K domains, the space savings over sorted strings is ~60KB while the implementation risk is high.

## Design

### File Format: K2RULEV3

Same overall structure as V2 (header → slice index → slice data), with domain slices changed from FST to sorted bytes.

```
+--------------------+
|  HEADER (64 bytes) |  Magic "K2RULEV3", version=1, slice_count, fallback_target
+--------------------+
|  SLICE INDEX       |  Array of SliceEntry (16 bytes each: type, target, offset, size, count)
+--------------------+
|  SLICE 0 DATA      |  Sorted domain bytes / CIDR array / GeoIP array
+--------------------+
|  SLICE 1 DATA      |
+--------------------+
|      ...           |
+--------------------+
```

**Header (64 bytes):** identical layout to V2, only magic changes to `K2RULEV3`.

**SliceEntry (16 bytes):** identical to V2. No changes.

**SliceType values:** same as V2:
- `0x01` SortedDomain (was FstDomain — internal format changed)
- `0x02` CidrV4
- `0x03` CidrV6
- `0x04` GeoIP
- `0x05` ExactIPv4
- `0x06` ExactIPv6

### Domain Slice Format (the key change)

Replaces FST with a flat, mmap-friendly sorted byte layout:

```
+---------------------------+
| count      (4 bytes, LE)  |  Number of domains
+---------------------------+
| offsets[0] (4 bytes, LE)  |  Byte offset into strings area
| offsets[1]                |
| ...                       |
| offsets[count-1]          |
| sentinel   (4 bytes, LE)  |  = total strings length (for bounds)
+---------------------------+
| strings area (variable)   |  Reversed, lowercased, dot-prefixed domains
|  "moc.elgoog."            |  ← ".google.com" reversed
|  "moc.ebutuoy."           |  ← ".youtube.com" reversed
|  ...                      |  (lexicographically sorted)
+---------------------------+
```

**All data is directly readable from mmap'd bytes. Zero deserialization.**

**Query algorithm** for `MatchDomain("www.youtube.com")`:
1. Normalize: `"www.youtube.com"` → lowercase
2. Generate suffixes to check: `[".www.youtube.com", ".youtube.com", ".com"]`
3. For each suffix, reverse it and binary search in the sorted strings area
4. Binary search reads offsets + string bytes directly from mmap'd memory
5. First match wins (slice ordering preserved by the file's slice index)

**Space estimate:**
- 10,000 domains × avg 20 chars = ~200KB strings + 40KB offsets = ~240KB uncompressed
- gzip compressed: ~60-80KB (similar to FST compressed)

**Query speed:**
- Binary search: log2(10000) ≈ 14 comparisons
- Each comparison: memcmp on ~20 bytes from mmap'd memory
- Total: < 1μs per domain lookup

### CIDR / GeoIP Slice Formats

**Unchanged from V2.** Already simple sorted arrays, already mmap-friendly.

- CidrV4: `[network_u32_BE(4) + prefix_len(1) + padding(3)]` × count = 8 bytes each
- CidrV6: `[network(16) + prefix_len(1) + padding(7)]` × count = 24 bytes each
- GeoIP: `[country_code(2) + padding(2)]` × count = 4 bytes each

### Porn Domain Unification

**Delete the `PORNFST` format entirely.** Porn domains become a standard K2RULEV3 file.

- File: `porn_domains.k2r.gz` — same format as `cn_blacklist.k2r.gz`
- Contains a single domain slice with `target = Reject`
- Heuristic detection (`internal/porn/heuristic.go`) unchanged
- Query path: `heuristic.IsPorn()` → miss → `SliceReader.MatchDomain()` → check target == Reject

### Generator: `cmd/k2rule-gen`

Go CLI tool replacing the Rust `k2rule-gen` binary.

```
cmd/k2rule-gen/
└── main.go          # CLI entry: generate-all, generate-porn

internal/
├── slice/
│   ├── format.go    # V3 constants + header/entry parsing (update magic)
│   ├── writer.go    # NEW: SliceWriter (sorted domain builder, CIDR, GeoIP)
│   ├── reader.go    # Update: remove FST, add sorted domain binary search
│   ├── mmap_reader.go  # Update: use new reader
│   └── fst.go       # DELETE
├── clash/
│   └── converter.go # NEW: Clash YAML → K2RULEV3 (port from Rust converter)
└── porn/
    ├── heuristic.go    # KEEP as-is
    ├── heuristic_test.go  # KEEP as-is
    ├── data.go         # KEEP as-is
    └── fst.go          # DELETE
```

**CI workflow change:**
```yaml
# Before (Rust)
- run: cargo build --release
- run: ./target/release/k2rule-gen generate-all -o output/ -v
- run: ./target/release/k2rule-gen generate-porn-fst -o output/porn_domains.fst.gz -v

# After (Go)
- run: go run ./cmd/k2rule-gen generate-all -o output/ -v
- run: go run ./cmd/k2rule-gen generate-porn -o output/porn_domains.k2r.gz -v
```

### Files to Delete

All Rust code and config:
- `Cargo.toml`, `Cargo.lock`
- `src/` (entire directory)
- `tests/` (Rust integration tests)
- `internal/slice/fst.go` (Go FST reader)
- `internal/porn/fst.go` (Go PORNFST reader)
- `src/bin/gen.rs` → replaced by `cmd/k2rule-gen/main.go`

### Public API Changes

**`remote.go`:** `DefaultRuleURL` stays the same path, file format changes transparently.

**`porn_remote.go`:**
- `DefaultPornURL` changes from `.fst.gz` to `.k2r.gz`
- Internal: `FSTChecker` → `SliceReader`

**`matcher.go`:** No changes to the public `Match()` / `MatchDomain()` API.

## Acceptance Criteria

1. **All Rust code deleted** — no `Cargo.toml`, no `src/` directory, no `.rs` files
2. **`cmd/k2rule-gen` generates valid K2RULEV3 files** from Clash YAML configs (cn_blacklist, cn_whitelist) and porn domain lists
3. **Go reader loads K2RULEV3 via mmap** — domain queries work directly on mmap'd bytes, no heap allocation per query
4. **Domain matching parity** — all existing Go test cases pass with the new format (suffix matching, ordering preserved, case insensitive)
5. **CIDR / GeoIP matching unchanged** — existing tests pass without modification
6. **Porn domain detection works** — heuristic + K2RULEV3 file lookup, unified API
7. **CI generates and deploys** — GitHub Actions workflow builds Go tool, generates files, pushes to release branch
8. **File size reasonable** — compressed K2RULEV3 files within 2x of current V2 sizes
9. **Zero external dependencies for core** — domain matching uses only stdlib (sort, bytes, encoding/binary)

## Technical Decisions

- **Sorted bytes + binary search over FST** — mmap-native, zero dependency, ~240KB for 10K domains is acceptable; FST saves ~60KB but costs ~500 lines of fragile cross-language format code (scrum-decided)
- **K2RULEV3 clean break** — no V2 backward compatibility needed; Rust (the only V2 writer) is being deleted (scrum-decided)
- **Porn unified into K2RULEV3** — one format, one code path; heuristic layer unchanged (scrum-decided)
- **Go CLI generator** — same language as reader eliminates format version drift by construction (scrum-decided)

## Version History

- 1.0 (2026-02-22): Initial spec — pure Go rewrite with K2RULEV3 sorted domain format
