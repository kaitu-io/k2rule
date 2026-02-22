# Plan: Pure Go Rewrite — K2RULEV3

## Meta

| Field | Value |
|-------|-------|
| Feature | pure-go-rewrite |
| Spec | docs/features/pure-go-rewrite.md |
| Date | 2026-02-22 |
| Complexity | complex |

## AC Mapping

| AC | Test | Task |
|----|------|------|
| AC1: All Rust code deleted | `TestNoRustFilesExist` (manual/CI check) | T6 |
| AC2: cmd/k2rule-gen generates valid K2RULEV3 | `TestSliceWriterBuildValid`, `TestConverterSimpleRules`, `TestConverterRuleProviders` | T1, T3, T4 |
| AC3: Go reader loads K2RULEV3 via mmap | `TestMmapSortedDomainMatch`, `TestMmapReaderFromGzipV3` | T2 |
| AC4: Domain matching parity | `TestSortedDomainBinarySearch`, `TestDomainSuffixMatching`, `TestDomainOrderingPreserved`, `TestDomainCaseInsensitive` | T2 |
| AC5: CIDR/GeoIP matching unchanged | `TestCidrV4Match`, `TestCidrV6Match`, `TestGeoIPMatch` (existing tests pass) | T2 |
| AC6: Porn domain detection works | `TestPornCheckerWithSliceReader`, `TestPornRemoteManagerK2R` | T5 |
| AC7: CI generates and deploys | CI workflow validated manually | T6 |
| AC8: File size reasonable | `TestGeneratedFileSizeReasonable` | T4 |
| AC9: Zero external dependencies for core | `TestNoDepsInReader` (build check, no new imports beyond stdlib + mmap) | T2 |

## Foundation Tasks

### T1: K2RULEV3 Format + SliceWriter

**Scope**: Update format constants to K2RULEV3. Create the Go SliceWriter that builds binary files with sorted domain slices (replacing Rust's FST-based writer). This is the foundation all other tasks depend on.
**Files**:
- `internal/slice/format.go` (modify: magic → `K2RULEV3`, rename `SliceTypeFstDomain` → `SliceTypeSortedDomain`)
- `internal/slice/writer.go` (create: `SliceWriter` with `AddDomainSlice`, `AddCidrV4Slice`, `AddCidrV6Slice`, `AddGeoIPSlice`, `Build`)
- `internal/slice/writer_test.go` (create)
**Depends on**: none
**TDD**:
- RED: Write failing tests for writer output format
  - `TestSliceWriterEmpty` — empty writer builds valid header-only file
  - `TestSliceWriterSingleDomain` — single domain slice with correct sorted bytes layout (count + offsets + sentinel + sorted reversed strings)
  - `TestSliceWriterMultipleDomains` — multiple domains sorted correctly, deduped
  - `TestSliceWriterCidrV4` — CIDR v4 slice matches Rust layout (8 bytes each, network BE + prefix_len + padding)
  - `TestSliceWriterCidrV6` — CIDR v6 slice matches Rust layout (24 bytes each)
  - `TestSliceWriterGeoIP` — GeoIP slice matches Rust layout (4 bytes each)
  - `TestSliceWriterMultipleSlices` — multiple slices with correct offsets in index
  - `TestSliceWriterFallbackTarget` — fallback target embedded in header
  - `TestDomainNormalization` — lowercase, dot-prefix, reverse, dedup
- GREEN: Implement SliceWriter
  - Domain normalization: lowercase → dot-prefix → reverse → sort → dedup
  - Domain slice layout: `count(4LE) + offsets[count+1](4LE each) + strings_area`
  - CIDR/GeoIP: port from Rust writer (already well-defined binary layout)
  - Header: 64 bytes, magic `K2RULEV3`, version=1
  - Build: assemble header + slice index + slice data, compute offsets
- REFACTOR:
  - [MUST] Rename `SliceTypeFstDomain` → `SliceTypeSortedDomain` in format.go (affects T2)
  - [SHOULD] Extract `normalizeDomain()` helper for reuse
**Acceptance**: Writer produces valid K2RULEV3 binary that reader (T2) can parse. Domain bytes are sorted and mmap-ready.

### T2: K2RULEV3 Sorted Domain Reader

**Scope**: Replace FST-based domain matching in both `SliceReader` (heap) and `MmapReader` (mmap) with binary search on sorted domain bytes. Delete `fst.go`. CIDR/GeoIP matching unchanged.
**Files**:
- `internal/slice/reader.go` (modify: `matchDomainInSlice` → binary search)
- `internal/slice/mmap_reader.go` (modify: `matchDomainInSlice` → binary search on mmap'd bytes)
- `internal/slice/reader_test.go` (create: domain matching tests using writer from T1)
- `internal/slice/fst.go` (delete)
**Depends on**: [T1]
**TDD**:
- RED: Write failing tests for V3 domain binary search
  - `TestSortedDomainBinarySearch` — exact match on reversed sorted domains
  - `TestDomainSuffixMatching` — `www.youtube.com` matches `.youtube.com` entry
  - `TestDomainOrderingPreserved` — `cn.bing.com→DIRECT` before `bing.com→PROXY` (first match wins across slices)
  - `TestDomainCaseInsensitive` — `Google.COM` matches `google.com`
  - `TestDomainNoMatch` — unknown domain returns nil
  - `TestMmapSortedDomainMatch` — same tests via MmapReader (write to temp file, mmap, query)
  - `TestMmapReaderFromGzipV3` — gzip decompression + mmap + V3 domain match
  - `TestCidrV4Match` — existing CIDR tests still pass (roundtrip through writer)
  - `TestCidrV6Match` — existing CIDR v6 tests still pass
  - `TestGeoIPMatch` — existing GeoIP tests still pass
  - `TestReaderRoundtrip` — write with SliceWriter → read with SliceReader → all matches correct
- GREEN: Implement binary search domain matching
  - Parse domain slice: read `count`, `offsets[count+1]`, then strings area
  - `binarySearchDomain(data, reversed)`: standard binary search comparing bytes
  - `matchDomainInSlice`: generate suffixes → reverse each → binary search
  - MmapReader: same algorithm, operates on `r.data[offset:offset+size]`
  - Delete `fst.go` (no longer needed)
- REFACTOR:
  - [MUST] Remove all FST imports and references from reader.go and mmap_reader.go
  - [SHOULD] Unify binary search helper between SliceReader and MmapReader (both operate on `[]byte`)
**Acceptance**: All domain/CIDR/GeoIP matching works via V3 format. `fst.go` deleted. Zero heap allocation per domain query on mmap path.

## Feature Tasks

### T3: Clash YAML Converter (Go)

**Scope**: Port the Rust `SliceConverter` to Go. Parses Clash YAML configs and generates K2RULEV3 binary via `SliceWriter`. Handles DOMAIN, DOMAIN-SUFFIX, IP-CIDR, IP-CIDR6, GEOIP, RULE-SET, MATCH rules. Supports domain/ipcidr/classical provider behaviors. Merges adjacent same-type same-target slices.
**Files**:
- `internal/clash/converter.go` (create)
- `internal/clash/converter_test.go` (create)
**Depends on**: [T1]
**TDD**:
- RED: Port Rust converter tests to Go
  - `TestConverterSimpleRules` — DOMAIN, DOMAIN-SUFFIX, GEOIP, MATCH rules
  - `TestConverterRuleProviders` — inline and external rule providers (domain behavior)
  - `TestConverterMergeAdjacentSlices` — adjacent same-type same-target slices merged
  - `TestConverterOrderingPreserved` — cn.bing.com→DIRECT before bing.com→PROXY
  - `TestConverterCidrRules` — IP-CIDR and IP-CIDR6 rules
  - `TestConverterLanGeoIP` — GEOIP,LAN expands to private CIDRs
  - `TestConverterExternalProvider` — set_provider_rules + convert
  - `TestConverterIpcidrProvider` — ipcidr behavior provider
  - `TestConverterClassicalProvider` — classical behavior with mixed rule types
  - `TestConverterProviderPayloadParsing` — YAML payload format and plain text format
- GREEN: Implement converter
  - YAML parsing with `gopkg.in/yaml.v3` (or stdlib `encoding/json` if YAML dep is unacceptable — but Clash configs are YAML)
  - Rule parsing: split by comma, dispatch by type
  - Provider handling: domain/ipcidr/classical behaviors
  - Adjacent slice merging: same algorithm as Rust
  - Build via `SliceWriter.Build()`
- REFACTOR:
  - [MUST] Export `LoadProvider(name, content)` and `SetProviderRules(name, rules)` for CLI use
  - [SHOULD] Extract CIDR parsing helpers to shared internal package
**Acceptance**: All Rust converter tests pass in Go. Round-trip: YAML → binary → reader → correct matches.

### T4: Generator CLI (cmd/k2rule-gen)

**Scope**: Go CLI replacing the Rust `k2rule-gen` binary. Commands: `generate-all` (Clash YAML → K2RULEV3) and `generate-porn` (porn domain list → K2RULEV3). Downloads rule providers and porn domain lists from CDN.
**Files**:
- `cmd/k2rule-gen/main.go` (create)
- `cmd/k2rule-gen/main_test.go` (create: integration tests)
**Depends on**: [T1, T3]
**TDD**:
- RED: Write integration tests
  - `TestGenerateAllFromClashYAML` — reads clash_rules/*.yml, produces valid K2RULEV3 .k2r.gz files
  - `TestGeneratePornDomains` — produces valid K2RULEV3 with target=Reject
  - `TestGeneratedFileSizeReasonable` — compressed size within expected bounds
  - `TestGzipOutputDecompressable` — output .k2r.gz decompresses to valid K2RULEV3
  - `TestPornHeuristicFiltering` — heuristic-detected domains excluded from output
- GREEN: Implement CLI
  - Use `flag` package (no external CLI deps)
  - `generate-all`: read clash_rules/*.yml, download providers via HTTP, convert, gzip, write
  - `generate-porn`: fetch meta.json from Bon-Appetit/porn-domains, download blocklist, filter heuristic, build single domain slice with target=Reject, gzip, write
  - Gzip compression: `compress/flate` with best compression
  - HTTP: `net/http` stdlib client
- REFACTOR:
  - [SHOULD] Extract HTTP download helper to reduce duplication
  - [SHOULD] Add progress logging with `slog`
**Acceptance**: `go run ./cmd/k2rule-gen generate-all -o output/ -v` produces cn_blacklist.k2r.gz and cn_whitelist.k2r.gz. `go run ./cmd/k2rule-gen generate-porn -o output/porn_domains.k2r.gz -v` produces porn K2RULEV3 file.

### T5: Porn Domain Unification

**Scope**: Replace PORNFST format with K2RULEV3. `PornChecker` uses `SliceReader` instead of `FSTChecker`. `PornRemoteManager` downloads `.k2r.gz` instead of `.fst.gz`. Delete `internal/porn/fst.go`.
**Files**:
- `porn.go` (modify: `PornChecker` uses `*slice.MmapReader` or `*slice.SliceReader`)
- `porn_remote.go` (modify: `DefaultPornURL` → `.k2r.gz`, cache path `.k2r.gz`)
- `config.go` (modify: `PornFile` comment `.fst.gz` → `.k2r.gz`)
- `internal/porn/fst.go` (delete)
- `porn_test.go` (create: test porn checker with V3 file)
**Depends on**: [T2]
**TDD**:
- RED: Write failing tests for unified porn checker
  - `TestPornCheckerWithSliceReader` — create K2RULEV3 with porn domains (target=Reject), verify IsPorn matches
  - `TestPornCheckerHeuristicFallback` — heuristic still works when no file loaded
  - `TestPornCheckerSuffixMatch` — `www.pornhub.com` matches `.pornhub.com` entry
  - `TestPornRemoteManagerK2R` — verify cache path uses `.k2r.gz` extension
  - `TestPornCheckerFromFile` — load from .k2r.gz file
- GREEN: Implement changes
  - `PornChecker`: replace `fst *porn.FSTChecker` with `reader *slice.SliceReader`
  - `NewPornCheckerFromFile`: use `slice.NewSliceReaderFromFile` instead of `porn.NewFSTCheckerFromFile`
  - `IsPorn`: heuristic first, then `reader.MatchDomain(domain)` checking if result target == Reject (uint8 value for TargetReject)
  - `DefaultPornURL`: change to `porn_domains.k2r.gz`
  - `getCachePath`: change extension to `.k2r.gz`
  - Delete `internal/porn/fst.go`
- REFACTOR:
  - [MUST] Remove all FST imports from porn.go
  - [SHOULD] Simplify PornChecker constructor variants (FromFile, FromBytes, FromGzip → just FromFile)
**Acceptance**: Porn detection works with K2RULEV3 file. Heuristic fallback preserved. `internal/porn/fst.go` deleted.

### T6: CI Workflow + Rust Deletion

**Scope**: Update GitHub Actions to use Go generator. Delete all Rust code (Cargo.toml, Cargo.lock, src/, tests/). Clean up CI workflow to remove Rust toolchain setup.
**Files**:
- `.github/workflows/generate-rules.yml` (modify: Go instead of Rust)
- `Cargo.toml` (delete)
- `Cargo.lock` (delete)
- `src/` (delete entire directory)
- `tests/` (delete if Rust-only)
- `go.mod` (modify: remove any unused deps)
- `go.sum` (modify: updated)
**Depends on**: [T4, T5]
**TDD**:
- RED: Verify Rust artifacts are gone
  - `TestNoRustFilesExist` — shell check: no .rs files, no Cargo.toml
  - `TestGoGeneratorBuilds` — `go build ./cmd/k2rule-gen` succeeds
  - `TestGoTestsPass` — `go test ./...` passes
- GREEN: Implement changes
  - Update workflow: replace `cargo build` with `go run ./cmd/k2rule-gen`
  - Remove Rust toolchain setup, cargo cache steps
  - Remove `build-and-test` job (Rust CI), replace with Go CI if needed
  - Delete all Rust files
  - Run `go mod tidy` to clean up deps
- REFACTOR:
  - [SHOULD] Add Go test step to CI workflow
  - [SHOULD] Simplify workflow (single job since Go compiles fast)
**Acceptance**: `go test ./...` passes. No `.rs` files in repo. CI workflow generates K2RULEV3 files using Go tool.

## Execution Graph

```
T1 (format + writer)
├── T2 (reader) ──── T5 (porn unification) ──┐
└── T3 (converter) ── T4 (generator CLI) ────┼── T6 (CI + cleanup)
                                              │
T2 ∥ T3  (parallel, no file overlap)         ┘
T4 + T5  (parallel after their deps, no file overlap)
```

**Parallel lanes**:
- Lane A: T1 → T2 → T5
- Lane B: T1 → T3 → T4
- Final: T6 (after T4 + T5)
