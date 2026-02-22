# Testing Strategies

## TS-001: Writer-First TDD for Binary Formats

**Feature:** pure-go-rewrite
**Date:** 2026-02-22

### Pattern

When implementing a binary format from scratch:
1. Write `writer_test.go` first — verify the binary layout byte-by-byte
2. Then write `reader_test.go` using the writer as the source of truth — no fixture files needed
3. Round-trip tests (`TestReaderRoundtrip`) catch layout mismatches between writer and reader

This pattern was used for `internal/slice/writer_test.go` and `internal/slice/reader_test.go`.

### Key Technique: Byte-Exact Layout Verification

```go
// In writer_test.go: verify "google.com" normalizes correctly
sentinel := binary.LittleEndian.Uint32(sliceData[8:12])
expectedStr := "moc.elgoog."
if sentinel != uint32(len(expectedStr)) { ... }
strArea := sliceData[12:]
got := string(strArea[:len(expectedStr)])
if got != expectedStr { ... }
```

Offset arithmetic is verified explicitly rather than relying on struct parsing. This catches silent padding or alignment bugs.

### Validating Tests

- `TestSliceWriterSingleDomain` — explicit byte-by-byte verification
- `TestReaderRoundtrip` — full write → read roundtrip with multiple slice types
- `TestMmapReaderFromGzipV3` — roundtrip via gzip + mmap path

---

## TS-002: Shared Test Helpers for Reader Variants

**Feature:** pure-go-rewrite
**Date:** 2026-02-22

### Pattern

`SliceReader` (heap) and `MmapReader` (mmap) have identical query APIs. Tests share helper functions:

```go
func buildData(t *testing.T, w *SliceWriter) []byte { ... }
func newSliceReader(t *testing.T, data []byte) *SliceReader { ... }
func newMmapReaderFromGzip(t *testing.T, data []byte) *MmapReader { ... }
```

`TestMmapSortedDomainMatch` reuses the same domain set and assertions as `TestSortedDomainBinarySearch` but routes through `newMmapReaderFromGzip`. This ensures both code paths stay in sync.

### Cleanup Pattern

`t.Cleanup(func() { r.Close() })` and `t.Cleanup(func() { os.Remove(f.Name()) })` ensure temp files and mmap handles are always released, even on test failure.

### Validating Tests

- `TestMmapSortedDomainMatch` — demonstrates parallel test coverage of reader variants
- `TestMmapReaderFromGzipV3` — full gzip → tempfile → mmap → query path

---

## TS-003: Clash Converter Tests — SetProviderRules Bypasses HTTP

**Feature:** pure-go-rewrite
**Date:** 2026-02-22

### Pattern

The Clash converter downloads rule-providers from HTTP URLs in production. For testing, `SetProviderRules(name, rules)` injects provider rules directly:

```go
converter := clash.NewSliceConverter()
converter.SetProviderRules("my-provider", []string{
    "+.google.com",
    "+.youtube.com",
})
data, _ := converter.Convert(yamlContent)
```

This makes converter tests fully deterministic and offline. The same pattern is used in the generator CLI for external provider content fetched over HTTP.

### LoadProvider for Text Content

`LoadProvider(name, content)` accepts either YAML payload format or plain text format. Tests cover both:

```go
// YAML payload format
converter.LoadProvider("prov", "payload:\n  - +.google.com\n  - +.youtube.com")

// Plain text format
converter.LoadProvider("prov", "+.google.com\n+.youtube.com")
```

### Validating Tests

- `TestConverterSimpleRules` — `internal/clash/converter_test.go`
- `TestConverterRuleProviders` — `internal/clash/converter_test.go`
- `TestConverterProviderPayloadParsing` — `internal/clash/converter_test.go`

---

## TS-004: CI Gate — No Rust Files

**Feature:** pure-go-rewrite
**Date:** 2026-02-22

### Pattern

After deleting all Rust code, a CI-style test guards against accidental re-introduction:

```go
// ci_check_test.go
func TestNoRustFilesExist(t *testing.T) {
    matches, _ := filepath.Glob("*.rs")
    if len(matches) > 0 { t.Errorf(...) }
    if _, err := os.Stat("Cargo.toml"); err == nil {
        t.Error("Cargo.toml should not exist")
    }
}
```

This is a structural test that runs as part of `go test ./...`. It serves as a regression guard — if someone accidentally adds a `.rs` file or `Cargo.toml`, the test fails immediately in CI.

### Validating Tests

- `TestNoRustFilesExist` — `ci_check_test.go`
- `TestGoGeneratorBuilds` — `ci_check_test.go`
