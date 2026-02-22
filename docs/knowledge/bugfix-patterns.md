# Bug Fix Patterns

## BF-001: Cross-Language Format Version Drift (FST)

**Feature:** pure-go-rewrite
**Date:** 2026-02-22
**Root Cause:** Rust `fst` crate writer and Go `fst` reader coupled to a specific crate version

### Symptom

Runtime errors `invalid magic` and `unsupported FST version` when loading K2RULEV2 rule files. The Rust `fst` crate occasionally changed its internal binary format between minor versions; the Go reader had no mechanism to detect or adapt to these changes.

### Pattern

Cross-language binary format coupling creates invisible version dependencies. When the writer (Rust) and reader (Go) are compiled independently, format mismatches can only be detected at runtime — typically in production.

### Fix Applied

Replace FST with a Go-native sorted-bytes format. Both writer (`SliceWriter`) and reader (`SliceReader`, `MmapReader`) live in the same module (`internal/slice`). Format changes are caught at compile time or immediately in tests.

### Prevention Rule

When a binary format has both a writer and reader, keep them in the same language and ideally the same module. Cross-language binary formats require explicit versioning contracts, test fixtures shared across languages, and CI that tests the roundtrip across language boundaries — costs that rarely justify the benefits for moderate-scale data.

### Validating Tests

- `TestSliceWriterMagicIsV3` — `internal/slice/writer_test.go`
- `TestReaderRoundtrip` — `internal/slice/reader_test.go`
- `TestMmapReaderFromGzipV3` — `internal/slice/reader_test.go`

---

## BF-002: Domain Suffix Matching False Positive — "notgoogle.com" vs "google.com"

**Feature:** pure-go-rewrite
**Date:** 2026-02-22
**Root Cause:** Naive suffix matching on reversed strings without dot-boundary enforcement

### Symptom

If implemented as a naive byte prefix match on the reversed string, `"moc.elgoog"` would match `"moc.elgoogton"` (reversed "notgoogle.com" contains reversed "google.com" as a suffix).

### Fix Applied

Domains are stored with a leading dot: `"google.com"` normalizes to `".google.com"` (reversed: `"moc.elgoog."`). Binary search looks for the exact reversed string including the leading dot. The dot acts as a boundary guard — `".notgoogle.com"` reversed is `"moc.elgoogton."` which does not equal `"moc.elgoog."`.

### Validating Tests

- `TestDomainNoMatch` (checks `"notgoogle.com"` does not match `"google.com"` entry) — `internal/slice/reader_test.go`
- `TestDomainSuffixMatching` — `internal/slice/reader_test.go`
- `TestSliceWriterDomainAlreadyDotPrefixed` (dedup: `"example.com"` and `".example.com"` normalize to same) — `internal/slice/writer_test.go`

---

## BF-003: Provider URL Extraction — Line-Based Parsing Instead of Full YAML

**Feature:** pure-go-rewrite
**Date:** 2026-02-22
**Root Cause:** Circular dependency risk if the cmd package imported its own YAML parsing through converter

### Symptom

The `extractProviderURLs` function in `cmd/k2rule-gen/main.go` needs to parse `rule-providers[*].url` from Clash YAML without duplicating the full Clash config struct. Initial approach tried to use a local YAML struct but left dead code (`_ = cfg`).

### Fix Applied

Implemented a line-by-line indent-tracking parser for the `rule-providers` section. Avoids importing a second YAML struct and keeps the provider URL extraction independent from the converter's full config parsing. The dead `cfg` variable was retained as a comment anchor but suppressed via `_ = cfg`.

### Note

This is a known rough edge. If the YAML structure of `rule-providers` changes (e.g., nested indentation), the line parser could fail silently. The generator handles this gracefully by logging a warning and continuing without downloads for providers it cannot resolve.

### Validating Tests

- `TestConverterRuleProviders` — `internal/clash/converter_test.go`
- Generator integration tests use `SetProviderRules` to bypass URL extraction in unit tests
