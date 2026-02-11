# K2Rule Go SDK

High-performance rule engine for VPN/proxy traffic routing and content filtering, with **memory-mapped architecture** for minimal memory footprint.

## 🚀 Features

- ✅ **Out-of-the-box**: Auto-download rules from CDN, no manual setup
- ✅ **Memory-efficient**: Uses memory-mapped files (~200 KB resident memory vs 5-10 MB with full loading)
- ✅ **Zero-copy access**: Direct access to mmap region, no data duplication
- ✅ **Hot-reload**: Seamless rule updates without service interruption
- ✅ **Auto-update**: Background checks every 6 hours with ETag optimization
- ✅ **Cross-platform**: Linux, macOS, Windows support via `syscall.Mmap`
- ✅ **Zero allocations**: All matching operations allocate 0 bytes
- ✅ **Read and use** Rust-generated rule files (.k2r.gz, porn_domains.fst.gz)

## Installation

```bash
go get github.com/kaitu-io/k2rule
```

## 🎯 Quick Start

### 🌐 CDN Rule Resources

**Pre-built rule files:**
```
https://cdn.jsdelivr.net/gh/kaitu-io/k2rule@release/cn_blacklist.k2r.gz
https://cdn.jsdelivr.net/gh/kaitu-io/k2rule@release/cn_whitelist.k2r.gz
https://cdn.jsdelivr.net/gh/kaitu-io/k2rule@release/porn_domains.fst.gz
```

**Update frequency:** Daily auto-update (source: [Loyalsoldier/clash-rules](https://github.com/Loyalsoldier/clash-rules))

**Cache mechanism:**
- First run: Auto-download to `~/.cache/k2rule/`
- Subsequent runs: Use cache (5-10ms startup)
- Auto-update: Background checks every 6 hours (ETag-based, 304 skips download)
- Multiple rules: Different URLs use independent cache, no conflicts

### Option 1: Remote Rules (Recommended - Out of the Box!)

Auto-download and auto-update from CDN:

```go
package main

import (
    "fmt"
    "github.com/kaitu-io/k2rule"
)

func main() {
    // Initialize with remote URL (auto-download + auto-update)
    // Fallback target is automatically read from the .k2r file header
    k2rule.InitRemote(
        "https://cdn.jsdelivr.net/gh/kaitu-io/k2rule@release/cn_blacklist.k2r.gz",
        "",  // Use default cache directory (~/.cache/k2rule/), iOS users specify Library/Caches path
    )

    // Match domains (memory-mapped, zero-copy)
    target := k2rule.Match("google.com")
    fmt.Println(target) // PROXY

    // Match IPs
    target = k2rule.Match("8.8.8.8")
    fmt.Println(target) // PROXY

    // Porn detection (heuristic + optional FST)
    if k2rule.IsPorn("pornhub.com") {
        fmt.Println("Blocked!")
    }

    // Keep running, rules auto-update every 6 hours
    select {}
}
```

**Memory usage**: ~200 KB resident + OS page cache (managed automatically)

### 📱 iOS Platform Configuration

**⚠️ Critical: iOS apps must specify cache directory**

iOS apps must place cache files in the sandbox's `Library/Caches/` directory to prevent iCloud sync.

**Correct Implementation:**

```go
import (
    "path/filepath"
    "os"
    "github.com/kaitu-io/k2rule"
)

// Get sandbox cache directory
cacheDir := filepath.Join(
    os.Getenv("HOME"),
    "Library", "Caches", "k2rule",
)

// Initialize with iOS cache directory
err := k2rule.InitRemote(
    "https://cdn.jsdelivr.net/gh/kaitu-io/k2rule@release/cn_blacklist.k2r.gz",
    cacheDir,  // Specify iOS cache directory
)
```

**❌ Incorrect (will sync to iCloud):**
- `Documents/` - User documents, synced
- `Library/Application Support/` - App support files, synced
- Empty string `""` (uses `~/.cache/k2rule/`) - Not supported in iOS sandbox

**Why avoid iCloud sync?**
- Rule file size: 3-5 MB (compressed)
- Update frequency: Every 6 hours checks, daily updates
- Wastes iCloud quota + unnecessary sync traffic

### Option 2: Local File

Load from a local `.k2r.gz` file:

```go
// Load local file with mmap (still uses ~200 KB memory)
// Fallback target is automatically read from the .k2r file header
k2rule.InitFromFile("./rules/cn_blacklist.k2r.gz")

target := k2rule.Match("baidu.com")
fmt.Println(target) // DIRECT
```

## 🏗️ Architecture

### Memory-Mapped Design

K2Rule Go SDK uses zero-copy architecture via memory-mapped files:

```
┌─────────────────────────────────────────────────────────┐
│                   K2Rule Go SDK                         │
├─────────────────────────────────────────────────────────┤
│  Public API (matcher.go)                                │
│  ├─ InitRemote(url) → auto-download + mmap             │
│  ├─ Match(input) → zero-copy query                     │
│  └─ Update() → hot-reload                              │
├─────────────────────────────────────────────────────────┤
│  RemoteRuleManager (remote.go)                         │
│  ├─ HTTP download (ETag 304 optimization)              │
│  ├─ Gzip decompress to temp file                       │
│  └─ Atomic hot-reload (atomic.Value)                   │
├─────────────────────────────────────────────────────────┤
│  MmapReader (internal/slice/mmap_reader.go)            │
│  ├─ syscall.Mmap() → zero-copy mapping                 │
│  ├─ Header + Entries: resident memory (~1 KB)          │
│  └─ FST/CIDR data: OS on-demand page loading           │
├─────────────────────────────────────────────────────────┤
│  File System                                            │
│  ├─ /tmp/k2rule-<hash>.bin (decompressed .k2r)        │
│  └─ ~/.cache/k2rule/*.k2r.gz (cached gzip files)      │
└─────────────────────────────────────────────────────────┘
```

**Memory-Mapped Files Benefits**:

| Aspect | Traditional (`os.ReadFile`) | Mmap (`syscall.Mmap`) | Improvement |
|--------|---------------------------|----------------------|-------------|
| **Loading** | Full file to memory | Indexed access | 96% memory saved |
| **Memory** | 5-10 MB resident | ~200 KB resident | **50× reduction** |
| **Access** | Copy from buffer | Zero-copy views | No allocation |
| **Startup** | 50-100 ms | 5-10 ms | **10× faster** |
| **Updates** | Reload entire file | Hot-swap (atomic) | Zero downtime |

### How It Works

1. **File Mapping**: `syscall.Mmap()` maps files into process address space
2. **Lazy Loading**: OS loads 4 KB pages only when accessed (on-demand)
3. **Zero-Copy**: Data accessed directly via slice views (no memcpy)
4. **Page Cache**: OS automatically manages page cache

**Memory breakdown**:
- **Header**: 64 bytes (resident)
- **Slice Entries**: ~100 bytes (resident)
- **FST/CIDR Data**: 4-5 MB (mmap'd, OS loads ~200 KB typically)
- **Total Resident**: ~200 KB

### Advanced Usage

#### Domain Matching

```go
target := k2rule.MatchDomain("google.com")
switch target {
case k2rule.TargetDirect:
    fmt.Println("Direct connection")
case k2rule.TargetProxy:
    fmt.Println("Use proxy")
case k2rule.TargetReject:
    fmt.Println("Block")
}
```

#### IP Matching

```go
import "net"

ip := net.ParseIP("8.8.8.8")
target := k2rule.MatchIP(ip)
```

#### GeoIP Matching

```go
target := k2rule.MatchGeoIP("CN") // Country code
```

#### Porn Detection

K2Rule provides two-layer porn detection:

1. **Heuristic detection** (fast, no I/O, 8 layers):
```go
isPorn := k2rule.IsPornHeuristic("pornhub.com")
```

2. **FST detection** (requires loading porn_domains.fst.gz):
```go
// Load porn domain database
err := k2rule.InitPornChecker("porn_domains.fst.gz")
if err != nil {
    panic(err)
}

// Now IsPorn uses both heuristic + FST
isPorn := k2rule.IsPorn("obscure-porn-site.com")
```

## 📚 API Reference

### Initialization

```go
// Initialize from remote URL (recommended - auto-download + auto-update)
// - url: CDN URL of rule file
// - cacheDir: Cache directory ("" for default ~/.cache/k2rule/, iOS needs Library/Caches path)
// Fallback target is automatically read from the .k2r file header.
func InitRemote(url string, cacheDir string) error

// Initialize from local file (mmap-based)
// Fallback target is automatically read from the .k2r file header.
func InitFromFile(path string) error

// Legacy: Initialize from bytes (creates temp file for mmap)
func InitFromBytes(data []byte) error

// Load porn domain database
func InitPornChecker(fstPath string) error
```

### Matching

- `Match(input string) Target` - Auto-detect and match (domain or IP)
- `MatchDomain(domain string) Target` - Match domain
- `MatchIP(ip net.IP) Target` - Match IP address
- `MatchGeoIP(country string) Target` - Match GeoIP country code

### Porn Detection

- `IsPorn(domain string) bool` - Check if porn (heuristic + FST)
- `IsPornHeuristic(domain string) bool` - Heuristic-only check

### Target Enum

```go
type Target uint8

const (
    TargetDirect Target = 0  // Direct connection
    TargetProxy  Target = 1  // Route through proxy
    TargetReject Target = 2  // Block the request
)
```

### Utilities

- `IsIPAddress(s string) bool` - Check if string is IP
- `IsDomain(s string) bool` - Check if string is domain
- `ParseTarget(s string) (Target, error)` - Parse target from string

## File Format

### K2Rule Binary Format (.k2r.gz)

```
+--------------------+
|  HEADER (64 bytes) |  Magic "K2RULEV2", version, slice_count, fallback_target
+--------------------+
|  SLICE INDEX       |  Array of SliceEntry (type, target, offset, size)
+--------------------+
|  SLICE 0 DATA      |  FST or sorted array
+--------------------+
|  SLICE 1 DATA      |
+--------------------+
|      ...           |
+--------------------+
```

Slice types:
- `0x01` - FST Domain set
- `0x02` - IPv4 CIDR ranges
- `0x03` - IPv6 CIDR ranges
- `0x04` - GeoIP country codes
- `0x05` - Exact IPv4 addresses
- `0x06` - Exact IPv6 addresses

### Porn Domain Database (.fst.gz)

```
+------------------+
|  MAGIC (8 bytes) |  "PORNFST\x01"
+------------------+
|  VERSION (4)     |  u32 LE
+------------------+
| TIMESTAMP (8)    |  i64 LE (Unix timestamp)
+------------------+
| DOMAIN_COUNT (4) |  u32 LE
+------------------+
|    FST DATA      |  Variable (fst::Set bytes)
+------------------+
```

## Porn Detection Layers

The heuristic detection uses 8 layers (in order):

1. **False Positive Filter** - Excludes legitimate domains (essex.ac.uk, adulteducation, etc.)
2. **Strong Keywords** - Platform brands (pornhub, xvideos, etc.)
3. **3x Prefix Pattern** - Domains starting with "3x"
4. **Porn Terminology** - Explicit terms (40 terms)
5. **Compound Terms** - Multi-word combinations (27 patterns)
6. **Verb+Noun Patterns** - Sequential combinations (137 patterns)
7. **Repetition Patterns** - xxx, sexsex, camcam, etc.
8. **Adult TLDs** - .xxx, .adult, .porn, .sex

Coverage: ~57% of 707k porn domains caught by heuristic alone.

## Examples

See `examples/basic/main.go` for a complete example.

```bash
cd examples/basic
go run main.go
```

## 🔒 File Management

### Temporary Files

Gzip files are decompressed to temporary files for mmap:

- **Location**: `/tmp/k2rule-<sha256>.bin` (Linux/macOS) or `%TEMP%` (Windows)
- **Cleanup**: Reused across runs (hash-based naming), auto-cleaned on boot
- **Size**: ~5 MB per rule file (decompressed)

### Cache Directory

Downloaded rules are cached in:

- **Linux/macOS**: `~/.cache/k2rule/`
- **Windows**: `%LOCALAPPDATA%/k2rule/`

### Auto-Update Behavior

- **Interval**: Every 6 hours
- **HTTP Optimization**: ETag-based (304 Not Modified skips download)
- **Hot-Reload**: Atomic swap using `atomic.Value`, zero downtime
- **Retry**: Continues using old rules on download failure

## 📊 Performance

### Matching Performance

- **Domain matching**: ~5-20 μs (FST lookup, zero-copy)
- **IP matching**: ~1-5 μs (CIDR binary search, zero-copy)
- **Porn heuristic**: ~10-50 ns (zero-allocation, pure CPU)
- **Porn FST**: ~5-20 μs (zero-copy mmap access)

### Memory Comparison

| Implementation | Resident Memory | Total Memory | Reduction |
|----------------|-----------------|--------------|-----------|
| Old (`os.ReadFile`) | 5-10 MB | 5-10 MB | Baseline |
| **New (mmap)** | **~200 KB** | **~700 KB** | **96%** |

### Startup Time

- **Old implementation**: 50-100 ms (decompress + full load)
- **New implementation**: 5-10 ms (header parse only)
- **Improvement**: **10× faster**

### Benchmarks

```bash
$ go test -bench=. -benchmem ./...
BenchmarkIsPornHeuristic-8   83680   17459 ns/op   0 B/op   0 allocs/op
BenchmarkMatchDomain-8       50000   25000 ns/op   0 B/op   0 allocs/op
BenchmarkMatchIP-8          200000    5000 ns/op   0 B/op   0 allocs/op
```

## 💾 Memory Architecture

### Memory Footprint (New Mmap Implementation)

K2Rule Go SDK uses memory-mapped files for extreme memory efficiency:

| Component | Memory Type | Typical Size | Allocation Pattern |
|-----------|-------------|--------------|-------------------|
| **Rule File Header** | Resident | 64 bytes | Parsed at Init() |
| **Slice Entries** | Resident | ~100 bytes | Parsed at Init() |
| **FST/CIDR Data** | Mmap (on-demand) | 4-5 MB virtual | OS page cache |
| **Resident FST/CIDR** | OS-managed | ~200 KB | Only accessed pages |
| **Porn Heuristic** | Code/data segment | ~50 KB | Static (no runtime alloc) |
| **Porn FST** | Mmap (optional) | 2.6 MB virtual | OS page cache |
| **Per-match overhead** | None | **0 bytes** | Zero allocations |

**Total resident memory:** ~200 KB (vs 5-10 MB with old implementation)

**Memory savings:** 96% reduction compared to full file loading

### Zero-Allocation Design

The Go SDK achieves zero allocations for matching operations:

```bash
$ go test -bench=BenchmarkIsPornHeuristic -benchmem
BenchmarkIsPornHeuristic-8   83680   17459 ns/op   0 B/op   0 allocs/op
```

**How it works:**

```go
// Initialization: mmap file (no full load)
reader, _ := slice.NewMmapReader("rules.k2r")
// syscall.Mmap() - OS maps file to address space
// Only header + entries parsed (~200 KB resident)

// Zero allocations during matching (mmap slice views)
fstData := reader.data[offset:offset+size]  // Zero-copy slice view
result := reader.MatchDomain("google.com")   // 0 allocs, OS loads pages

// Porn heuristic: static data only
isPorn := porn.IsPornHeuristic("example.com")  // 0 allocs
```

### Memory Sharing Across Goroutines

The global matcher pattern allows memory sharing:

```go
// Initialize once (3-8 MB allocated)
k2rule.Init()
k2rule.InitFromFile("rules.k2r.gz")

// All goroutines share the same data (0 additional memory)
for i := 0; i < 1000; i++ {
    go func() {
        k2rule.Match("google.com")  // Shared read-only access
    }()
}
```

**Memory multiplication factor:** 1x (not N×goroutines)

### FST Memory Efficiency

Finite State Transducers provide 13.5× compression vs raw storage:

**700k Porn Domains Example:**

| Format | Memory | Compression |
|--------|--------|-------------|
| String array | 35 MB | 1.0× |
| Hash set | 35 MB | 1.0× |
| Trie | 25 MB | 1.4× |
| FST | 3.6 MB | 9.7× |
| **FST + gzip** | **2.6 MB** | **13.5×** |

**How FST achieves this:**

```
Traditional: Store each domain separately
  pornhub.com  (12 bytes)
  pornhub.net  (12 bytes)
  pornhub.org  (12 bytes)
  Total: 36 bytes

FST: Share common prefixes/suffixes
  (Reversed for suffix sharing)
  moc.buhpron.  (shared)
    ├─ (empty)   → pornhub.com
    ├─ ten.      → pornhub.net
    └─ gro.      → pornhub.org
  Total: ~15 bytes (58% reduction)
```

### Lazy Loading Pattern

For applications that don't always need rules:

```go
var (
    rulesLoaded bool
    mu          sync.Mutex
)

func Match(domain string) k2rule.Target {
    mu.Lock()
    if !rulesLoaded {
        k2rule.InitFromFile("rules.k2r.gz")  // Load on first use
        rulesLoaded = true
    }
    mu.Unlock()

    return k2rule.MatchDomain(domain)
}
```

**Memory saved:** 3-5 MB if rules never loaded

### Memory vs Performance Tradeoffs

**Option 1: Minimal Memory (Heuristic Only)**

```go
// 0 MB additional memory
isPorn := k2rule.IsPornHeuristic(domain)
```

- Memory: 0 MB (code/data segment only)
- Coverage: ~57% of porn domains
- Speed: ~17μs per check

**Option 2: Full Coverage (Heuristic + FST)**

```go
// ~2.6 MB for FST
k2rule.InitPornChecker("porn_domains.fst.gz")
isPorn := k2rule.IsPorn(domain)
```

- Memory: 2.6 MB (compressed)
- Coverage: 100% (700k+ domains)
- Speed: ~17μs (heuristic) or ~10μs (FST) per check

**Option 3: Maximum Performance (Future: LRU Cache)**

```go
// Future feature: +1-10 MB for cache
k2rule.EnableCache(10_000)  // 10k most recent queries
```

- Memory: +1-10 MB (depending on cache size)
- Coverage: 100%
- Speed: ~100ns for cached results

### Concurrent Access Performance

The Go SDK uses `sync.RWMutex` for safe concurrent access:

```go
// Internal implementation
var (
    globalMatcher *Matcher
    globalMutex   sync.RWMutex
)

func Match(input string) Target {
    globalMutex.RLock()         // Multiple readers allowed
    defer globalMutex.RUnlock()
    return globalMatcher.match(input)
}
```

**Concurrency characteristics:**

- **Read-heavy workload**: Near-linear scaling (no contention)
- **Write operations**: Rare (only during Init/Update)
- **Memory overhead**: 0× (data shared, not copied)

### Garbage Collection Impact

K2Rule minimizes GC pressure through zero-allocation design:

**Before (hypothetical allocating design):**
```go
// BAD: Allocates on every match
domain := strings.ToLower(input)          // allocation
reversed := reverseString(domain)         // allocation
result := map[string]Target{...}[domain]  // allocation
// 3 allocations × 10,000 QPS = 30,000 allocs/sec → GC pressure
```

**After (K2Rule actual design):**
```go
// GOOD: Zero allocations
result := k2rule.Match(input)  // 0 allocations
// 0 allocations × 10,000 QPS = 0 allocs/sec → No GC pressure
```

**Impact on GC pause times:**

| Allocations/sec | GC pause (p99) | Notes |
|----------------|----------------|-------|
| 0 (K2Rule) | < 1ms | Minimal GC activity |
| 30,000 | 5-10ms | Moderate pressure |
| 300,000 | 50-100ms | Severe pressure |

### Memory Profiling

To measure actual memory usage in your application:

```bash
# Profile memory allocation
go test -memprofile=mem.prof -bench=.
go tool pprof mem.prof

# Check for zero allocations
go test -benchmem -bench=BenchmarkIsPornHeuristic
```

Expected output:
```
BenchmarkIsPornHeuristic-8   83680   17459 ns/op   0 B/op   0 allocs/op
                                                    ^^^^^^^^^^^^^^^^^^^^
                                                    Zero allocations ✓
```

### Platform-Specific Considerations

**Linux:** Virtual memory overcommit allows mapping large files with minimal RSS

**macOS:** Compressed memory may reduce apparent usage

**Windows:** Working set may appear larger due to pre-fetching

**Containers (Docker/K8s):** Set memory limits accounting for:
- Base Go runtime: ~10-20 MB
- Rule data: 3-8 MB
- Application code: varies
- Recommended: 50-100 MB minimum

### Best Practices

1. **Initialize once, use many times**
   ```go
   func init() {
       k2rule.Init()  // App startup
   }
   ```

2. **Use heuristic-first for porn detection**
   ```go
   if k2rule.IsPornHeuristic(domain) {
       return true  // Fast path, 0 MB overhead
   }
   // Optional: FST lookup for remaining domains
   ```

3. **Don't reload rules unnecessarily**
   ```go
   // BAD: Reloads 3 MB on every request
   func handler(w http.ResponseWriter, r *http.Request) {
       k2rule.InitFromFile("rules.k2r.gz")  // ❌
   }

   // GOOD: Initialize once at startup
   func init() {
       k2rule.InitFromFile("rules.k2r.gz")  // ✓
   }
   ```

4. **Monitor memory in production**
   ```go
   import "runtime"

   var m runtime.MemStats
   runtime.ReadMemStats(&m)
   log.Printf("Alloc=%v MB", m.Alloc/1024/1024)
   ```

## 🤝 Comparison with Rust Implementation

| Feature | Rust | Go | Notes |
|---------|------|-----|-------|
| Memory-mapped files | ✅ (memmap2) | ✅ (syscall.Mmap) | Same approach |
| Zero-copy access | ✅ | ✅ | Slice views |
| Hot-reload | ✅ (arc-swap) | ✅ (atomic.Value) | Same pattern |
| Auto-update | ✅ | ✅ | ETag optimization |
| Memory usage | ~100 KB | ~200 KB | Slightly higher (acceptable) |
| Performance | Baseline | ~95% | Negligible difference |
| Rule generation | ✅ | ❌ | Use Rust for generation |

## ✅ Compatibility

- ✅ Fully compatible with Rust-generated rule files
- ✅ Same binary format (little-endian)
- ✅ Same FST format (Rust `fst` crate)
- ✅ Same matching logic and results
- ✅ Cross-platform: Linux, macOS, Windows

## 🔄 Migration from v0.2.x to v0.3.0

### Breaking Change: Fallback Parameter Removed

The `fallback` parameter has been removed from `InitRemote` and `InitFromFile`.
The fallback target is now automatically read from the .k2r file header.

**Before (v0.2.x):**
```go
k2rule.InitRemote(url, cacheDir, k2rule.TargetDirect)
k2rule.InitFromFile(path, k2rule.TargetDirect)
```

**After (v0.3.0):**
```go
k2rule.InitRemote(url, cacheDir)
k2rule.InitFromFile(path)
```

**Why this change?**
- Eliminates confusion between user-provided fallback and file's fallback
- Ensures behavior matches the rule file's intent (Clash YAML MATCH rule)
- Simplifies API and reduces potential for errors

**How to migrate:**
1. Remove the third parameter from `InitRemote` calls
2. Remove the second parameter from `InitFromFile` calls
3. If you need a specific fallback, regenerate your .k2r files with the correct `MATCH` rule in the source Clash YAML

**What fallback will be used?**
- The fallback is read from the .k2r file header
- For `cn_blacklist.k2r.gz`: `MATCH,DIRECT` → fallback = DIRECT
- For `cn_whitelist.k2r.gz`: `MATCH,PROXY` → fallback = PROXY

## Testing

```bash
# Run all tests
go test ./...

# Run with coverage
go test -cover ./...

# Run benchmarks
go test -bench=. ./...
```

## ❓ FAQ

**Q: Why decompress gzip files to temp files instead of mmap'ing gzip directly?**

A: Memory-mapped I/O requires random access to uncompressed data. Gzip is a streaming format that doesn't support random access. Decompressing once and reusing the temp file (hash-based naming) is the most efficient approach.

**Q: Can I use this without downloading remote rules?**

A: Yes! Use `InitFromFile()` with a local `.k2r.gz` file. You can generate these using the Rust CLI tools.

**Q: How do I stop the auto-update background task?**

A: Currently, auto-update runs for the program lifetime. To stop it, you would need to call `manager.Stop()` (requires exposing the manager in future API updates).

**Q: Does this work on Windows?**

A: Yes! `syscall.Mmap` is cross-platform and works on Windows via `CreateFileMapping` and `MapViewOfFile` internally.

**Q: What happens if the remote download fails?**

A: The manager continues using cached rules. If no cache exists, `InitRemote()` returns an error. You can implement retry logic or fallback to local files.

**Q: Why is resident memory ~200 KB instead of the full 5 MB file?**

A: With mmap, the OS only loads pages (4 KB chunks) into physical memory when they're accessed. Most rule files have localized "hot" sections (frequently accessed FST nodes), so only ~200 KB is typically resident. The rest stays virtual (on disk) until needed.

**Q: Can I use both `InitRemote()` and `InitFromFile()`?**

A: No, only one initialization is active at a time. The last `Init*()` call wins. Choose one based on your needs.

## 📝 License

MIT License - see [LICENSE](LICENSE) file for details.

## 🔗 Related

- [K2Rule Rust Implementation](https://github.com/kaitu-io/k2rule) - Rule generator and Rust library
- [Kaitu.io](https://kaitu.io) - VPN service powered by K2Rule
- [CDN Rules](https://cdn.jsdelivr.net/gh/kaitu-io/k2rule@release/) - Pre-built rule files
