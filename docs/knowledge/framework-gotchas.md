# Framework Gotchas

## FG-001: mmap Requires a Real File — Cannot mmap a Reader or []byte

**Feature:** pure-go-rewrite
**Date:** 2026-02-22

### Gotcha

`mmap.Map()` from `github.com/edsrzf/mmap-go` requires an `*os.File`. You cannot mmap an in-memory buffer or a decompressed gzip stream directly.

### Consequence

`NewMmapReaderFromGzip` must decompress to a temp file first, then mmap the temp file. This doubles disk usage but is the only way to combine mmap with compressed storage.

### Pattern

```go
// Decompress gzip to temp file with deterministic name (SHA256 of gzip path)
tmpPath := filepath.Join(dir, fmt.Sprintf("k2rule-%s.bin", hash))
if _, err := os.Stat(tmpPath); err != nil {
    decompressGzip(gzipPath, tmpPath)
}
return NewMmapReader(tmpPath) // now mmap the uncompressed file
```

The SHA256-based name means repeated calls reuse the same temp file. Temp files are not automatically cleaned up — they persist in the cache directory. This is intentional (avoid repeated decompression).

---

## FG-002: sort.Search Semantics — Returns Insertion Point, Not Match

**Feature:** pure-go-rewrite
**Date:** 2026-02-22

### Gotcha

`sort.Search(n, f)` returns the smallest index `i` where `f(i)` is true. When used for exact-match binary search, the caller must check that `array[i] == target` — `sort.Search` does not do this.

### Pattern (used in domain binary search)

```go
idx := sort.Search(count, func(j int) bool {
    return getDomainAt(j) >= target
})
if idx < count && getDomainAt(idx) == target {
    return true
}
```

Without the `idx < count && getDomainAt(idx) == target` guard, a search for a domain greater than all stored domains would return `count` (out of bounds), causing a panic or false positive.

---

## FG-003: binary.Read with Unexported Fields Causes Panic

**Feature:** pure-go-rewrite
**Date:** 2026-02-22

### Gotcha

`binary.Read(buf, binary.LittleEndian, &struct)` panics if the struct has unexported fields. The `SliceHeader` struct uses unexported `_reserved1`, `_reserved2` fields for padding — `binary.Read` cannot handle these.

### Fix Applied

Read fields individually in order rather than reading the whole struct at once:

```go
binary.Read(buf, binary.LittleEndian, &h.Magic)
binary.Read(buf, binary.LittleEndian, &h.Version)
// ...
binary.Read(buf, binary.LittleEndian, &h._reserved1) // read reserved separately
```

This also makes the field layout explicit and easier to audit against the spec.

---

## FG-004: gopkg.in/yaml.v3 — Inline Payload vs Full Config Parsing

**Feature:** pure-go-rewrite
**Date:** 2026-02-22

### Gotcha

The Clash YAML format uses two different structures for provider content:
1. Full config: `rule-providers:` with nested keys
2. Provider payload files: `payload:` with a list of rule strings

`gopkg.in/yaml.v3` unmarshals these into different Go struct shapes. `SliceConverter.LoadProvider` handles both by trying YAML unmarshal first, falling back to plain-text line parsing:

```go
var doc struct { Payload []string `yaml:"payload"` }
if yaml.Unmarshal([]byte(content), &doc) == nil && len(doc.Payload) > 0 {
    // YAML payload format
    return nil
}
// Fall back to plain text: one entry per line
```

Note: A successful unmarshal with an empty Payload list falls through to plain text. This handles plain text files that happen to contain valid YAML (e.g., a file with only comments).

---

## FG-005: GEOIP,LAN Is a Special Case — Not a Country Code

**Feature:** pure-go-rewrite
**Date:** 2026-02-22

### Gotcha

Clash YAML `GEOIP,LAN,DIRECT` is not a GeoIP country lookup — it means "LAN/private IPs should go DIRECT". The `SliceConverter` must recognize `"LAN"` and expand it to private CIDR ranges.

### Private Ranges Expanded

```
IPv4: 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16
IPv6: fc00::/7, fe80::/10, ::1/128
```

These are stored as `CidrV4` and `CidrV6` slices, not `GeoIP` slices.

### Validating Tests

- `TestConverterLanGeoIP` — `internal/clash/converter_test.go`
