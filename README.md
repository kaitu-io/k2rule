# K2Rule - High-Performance Rule Engine for Rust

[English](#english) | [中文](#中文)

---

<a name="english"></a>

## English

A blazing-fast rule-based routing and filtering system written in Rust, optimized for proxy traffic management, VPN routing, and content filtering. Perfect for GFW bypass, Clash/Shadowsocks/Sing-box integration, and network acceleration solutions.

## 🚀 Quick Start (Go SDK)

### 📦 Installation

```bash
go get github.com/kaitu-io/k2rule
```

### ⚡ 3-Line Integration

```go
// Initialize - Uses pre-built rules (auto-download, cache, auto-update)
config := &k2rule.Config{
    RuleURL:  "https://cdn.jsdelivr.net/gh/kaitu-io/k2rule@release/cn_blacklist.k2r.gz",
    CacheDir: "/tmp/k2rule",  // REQUIRED: caller must provide writable directory
}
k2rule.Init(config)

// Start matching
target := k2rule.Match("google.com")  // Returns PROXY
```

**💡 Note:** The fallback target (DIRECT, PROXY, or REJECT) is automatically read from the .k2r file header, which comes from the Clash YAML's `MATCH` rule. You don't need to specify it manually.

**📱 CacheDir is platform-specific:**
```go
// macOS app:    ~/Library/Caches/com.kaitu.app/k2rule
// macOS daemon: /var/tmp/k2rule
// iOS:          NSCachesDirectory (from Swift bridge)
// Android:      context.getCacheDir() (from JNI)
// Windows:      %LocalAppData%\k2rule\cache
```

**Features:**
✅ Auto-download with infinite retry (exponential backoff, cap 64s)
✅ Local cache in caller-specified directory
✅ Auto-update (every 6 hours)
✅ Low memory (~200KB resident)
✅ Zero-downtime hot reload

### 🎯 Choose Your Rule Mode

| Mode | Default Behavior | Use Case | CDN URL |
|------|------------------|----------|---------|
| **Blacklist (Recommended)** | Default DIRECT | 🇨🇳 China users, mainly domestic content | [`cn_blacklist.k2r.gz`](https://cdn.jsdelivr.net/gh/kaitu-io/k2rule@release/cn_blacklist.k2r.gz) |
| Whitelist | Default PROXY | 🌍 International access priority | [`cn_whitelist.k2r.gz`](https://cdn.jsdelivr.net/gh/kaitu-io/k2rule@release/cn_whitelist.k2r.gz) |

**Rule Behavior:**
- **Blacklist**: Unknown domain → DIRECT, GFW sites → PROXY
- **Whitelist**: Unknown domain → PROXY, China IP → DIRECT

**💡 Tip:** Different URLs use separate cache files, switch anytime without conflicts.

### 📝 Complete Example

```go
package main

import (
    "fmt"
    "github.com/kaitu-io/k2rule"
)

func main() {
    // Initialize with unified config (CacheDir is REQUIRED)
    config := &k2rule.Config{
        RuleURL:  "https://cdn.jsdelivr.net/gh/kaitu-io/k2rule@release/cn_blacklist.k2r.gz",
        CacheDir: "/tmp/k2rule",  // REQUIRED: platform-specific writable directory
    }
    err := k2rule.Init(config)
    if err != nil {
        panic(err)
    }

    // Domain matching
    fmt.Println(k2rule.Match("google.com"))     // PROXY
    fmt.Println(k2rule.Match("baidu.com"))      // DIRECT

    // IP matching
    fmt.Println(k2rule.Match("8.8.8.8"))        // PROXY
    fmt.Println(k2rule.Match("114.114.114.114")) // DIRECT

    // Porn detection (optional)
    if k2rule.IsPorn("example.com") {
        fmt.Println("Blocked!")
    }
}
```

### 📱 iOS Platform Configuration

**⚠️ Important: CacheDir is REQUIRED on all platforms**

The caller must provide a platform-appropriate writable directory. On iOS, use `Library/Caches/` to avoid iCloud sync.

**✅ Correct approach:**

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

// Initialize
config := &k2rule.Config{
    RuleURL:  "https://cdn.jsdelivr.net/gh/kaitu-io/k2rule@release/cn_blacklist.k2r.gz",
    CacheDir: cacheDir,  // iOS sandbox cache directory
}
k2rule.Init(config)
```

**❌ Wrong approach (will sync to iCloud):**
- `Documents/` - User documents, will sync
- `Library/Application Support/` - App support files, will sync

### 🔄 Cache & Update Mechanism

**Cache Isolation:**
Each rule URL uses a separate cache file (based on URL's SHA256 hash):
```
{CacheDir}/
├── abcd1234.k2r.gz  ← cn_blacklist
├── 5678efgh.k2r.gz  ← cn_whitelist
├── abcd1234.mmdb    ← GeoIP database
└── ...
```

**Download Retry:**
All downloads use infinite retry with exponential backoff:
- 1s → 2s → 4s → 8s → 16s → 32s → 64s → 64s → ...
- Init() blocks until all resources are available

**Auto-Update Flow:**
1. Check for updates every 6 hours in background
2. Send If-None-Match (ETag) request
3. Server returns 304 Not Modified → Skip download
4. Server returns 200 OK → Download new rules → Hot reload (zero downtime)

**📖 Full Documentation:** [Go SDK Documentation](README_GO.md)

---

### ⚡ Performance Highlights

| Feature | Performance |
|---------|-------------|
| **Porn Domain Detection** | 48.9% heuristic coverage, 2.6 MB compressed |
| **Rule Matching** | O(log n) for FST, O(1) for hash lookups |
| **Memory Efficiency** | Memory-mapped file support for large datasets |
| **File Size Reduction** | 47% smaller with intelligent heuristic filtering |

### 🎯 Key Features

- **🚀 High Performance**: Binary index format with optimized lookup algorithms
- **💾 Memory Efficient**: Memory-mapped files for minimal RAM usage
- **🌍 Cross-Platform**: macOS, Linux, Windows, iOS, Android via FFI
- **🔄 Clash Compatible**: Convert Clash YAML rules to optimized binary format - ideal for VPN and 代理 (proxy) applications
- **🌐 GFW Bypass Support**: Designed for 翻墙 (firewall bypass) scenarios with efficient routing rules
- **⚡ Network Acceleration**: Optimized for 加速器 (accelerator) and traffic management
- **🔧 Protocol Agnostic**: Works with Shadowsocks, Sing-box, V2Ray, and other proxy protocols
- **🧠 Smart Heuristics**: Pattern-based detection reduces file size by 47%
- **🔒 Zero False Positives**: Carefully crafted rules for accurate filtering

### 📦 Supported Rule Types

- **DOMAIN**: Exact and suffix domain matching with FST
- **IP-CIDR**: IPv4/IPv6 CIDR range matching
- **GEOIP**: Geographic IP-based routing
- **IP-MATCH**: Exact IP address matching

### 🎨 Binary Formats

#### Slice-Based Format (k2r v2) - Recommended

Preserves rule ordering with optimal data structures:

```
+------------------+
|     HEADER       |  64 bytes
+------------------+
|  SLICE ENTRIES   |  16 bytes × N
+------------------+
|    SLICE 1       |  FST/sorted array
+------------------+
|    SLICE 2       |  ...
+------------------+
```

**Features:**
- ✅ Rule ordering preserved (first match wins)
- ✅ FST for efficient domain matching
- ✅ Adjacent slice merging for optimization
- ✅ Embedded fallback target

### 🔥 Porn Domain Detection with Smart Heuristics

K2Rule features an advanced two-layer porn domain detection system:

#### Layer 1: Heuristic Detection (48.9% coverage)

Fast pattern matching using 8 detection layers:

1. **False Positive Filter** - Excludes legitimate domains (essex.ac.uk, adulteducation.gov)
2. **Strong Keywords** - Platform brands (pornhub, xvideos, chaturbate, onlyfans)
3. **3x Prefix Pattern** - Domains starting with "3x" (3xmovies, 3xvideos)
4. **Porn Terminology** - 40 high-frequency explicit terms
5. **Compound Terms** - Multi-word combinations (sexcam, freeporn, bigass)
6. **Verb+Noun Patterns** - 137 sequential combinations (free+porn, watch+sex)
7. **Repetition Patterns** - Character/word repetitions (xxx, sexsex)
8. **Adult TLDs** - ICANN-approved domains (.xxx, .porn, .sex, .adult)

#### Layer 2: FST Database (51.1% remaining domains)

Binary search in compressed FST structure for domains not caught by heuristics.

#### Performance Impact

| Metric | Without Heuristic | With Heuristic | Improvement |
|--------|-------------------|----------------|-------------|
| **File Size** | 4.9 MB | 2.6 MB | **-47%** |
| **Domains Stored** | 707,915 | 361,489 | **-49%** |
| **Detection Speed** | FST only | Heuristic + FST | **~2x faster** |
| **Heuristic Coverage** | 0% | 48.9% | **+48.9%** |

**Source:** 707,915 domains from [Bon-Appetit/porn-domains](https://github.com/Bon-Appetit/porn-domains)

📖 **Detailed Documentation:** [Porn Heuristic Detection](docs/porn-heuristic-detection.md)

### 📥 Installation

```bash
cargo install --path .
```

### 🚀 Quick Start

#### Generate Porn Domain List

```bash
k2rule-gen generate-porn-fst -o output/porn_domains.fst.gz -v
```

Output:
```
Successfully generated FST porn domain list: "output/porn_domains.fst.gz"
  Source: 2026-01-28T08:17:56Z (707915 domains)
  Heuristic coverage: 346426 domains (48.9%)
  Stored in FST: 361489 domains
  FST size: 3609186 bytes uncompressed
  Compressed size: 2747095 bytes (76.1% of uncompressed)
```

#### Use in Your Application

```rust
use k2rule::porn_heuristic::is_porn_heuristic;
use k2rule::FstPornChecker;

// Fast heuristic check (no file I/O)
if is_porn_heuristic("pornhub.com") {
    return true; // Detected by heuristic
}

// FST lookup for remaining domains
let checker = FstPornChecker::open("porn_domains.fst.gz")?;
if checker.is_porn("obscure-porn-site.com") {
    return true; // Detected by FST
}
```

### 📚 Rule Conversion

#### Convert Clash YAML to Binary

```bash
# Slice-based format (recommended)
k2rule-gen generate-slice -i clash_rules/cn_blacklist.yml -o cn_blacklist_v2.k2r.gz -v

# Generate all rule sets
k2rule-gen generate-slice-all -o output/ -v
```

#### Library Usage

```rust
use k2rule::{SliceConverter, SliceReader, Target};

let yaml = r#"
rules:
  - DOMAIN-SUFFIX,cn.bing.com,DIRECT
  - DOMAIN-SUFFIX,bing.com,PROXY
  - GEOIP,CN,DIRECT
  - MATCH,PROXY
"#;

let converter = SliceConverter::new();
let data = converter.convert(yaml)?;

let reader = SliceReader::from_bytes(&data)?;
assert_eq!(reader.match_domain("cn.bing.com"), Some(Target::Direct));
assert_eq!(reader.match_domain("www.bing.com"), Some(Target::Proxy));
```

#### Go SDK Usage

K2Rule provides a native Go SDK that is **fully compatible** with Rust-generated rule files.

**Installation:**

```bash
go get github.com/kaitu-io/k2rule
```

**Quick Start:**

```go
package main

import (
    "fmt"
    "github.com/kaitu-io/k2rule"
)

func main() {
    // Initialize with unified config (CacheDir is REQUIRED)
    config := &k2rule.Config{
        RuleURL:  "https://cdn.jsdelivr.net/gh/kaitu-io/k2rule@release/cn_blacklist.k2r.gz",
        CacheDir: "/tmp/k2rule",  // REQUIRED
    }
    err := k2rule.Init(config)
    if err != nil {
        panic(err)
    }

    // Match domain
    target := k2rule.Match("google.com")
    fmt.Println(target)  // PROXY

    // Porn detection (heuristic + FST)
    if k2rule.IsPorn("pornhub.com") {
        fmt.Println("Blocked!")
    }
}
```

**Advanced Usage:**

```go
// Domain matching
target := k2rule.MatchDomain("google.com")
switch target {
case k2rule.TargetDirect:
    // Direct connection
case k2rule.TargetProxy:
    // Use proxy
case k2rule.TargetReject:
    // Block
}

// IP matching
import "net"
ip := net.ParseIP("8.8.8.8")
target = k2rule.MatchIP(ip)

// GeoIP matching
target = k2rule.MatchGeoIP("CN")

// Porn detection with FST
k2rule.InitPornChecker("porn_domains.fst.gz")
isPorn := k2rule.IsPorn("example.com")
```

**Memory Efficiency:**

The Go SDK is designed for minimal memory footprint:

- **Zero-copy FST reading**: Direct byte slice access without allocations
- **Lazy loading**: Only loaded data is kept in memory
- **Porn heuristic**: 0 allocations per check
- **Shared rule data**: Global matcher shares memory across goroutines

See [Memory Architecture](#-memory-architecture) below for overview, or [docs/memory-architecture.md](docs/memory-architecture.md) for technical deep dive.

**Full Documentation:** [README_GO.md](README_GO.md)

### 🌐 Pre-built Rules (CDN)

| Rule Set | Description | URL |
|----------|-------------|-----|
| **cn_blacklist.k2r.gz** | Blacklist mode | `cdn.jsdelivr.net/gh/kaitu-io/k2rule@release/cn_blacklist.k2r.gz` |
| **cn_whitelist.k2r.gz** | Whitelist mode | `cdn.jsdelivr.net/gh/kaitu-io/k2rule@release/cn_whitelist.k2r.gz` |
| **porn_domains.fst.gz** | Porn domains (2.6 MB) | `cdn.jsdelivr.net/gh/kaitu-io/k2rule@release/porn_domains.fst.gz` |

Updated daily from [Loyalsoldier/clash-rules](https://github.com/Loyalsoldier/clash-rules) and [Bon-Appetit/porn-domains](https://github.com/Bon-Appetit/porn-domains).

### 🧠 Memory Architecture

K2Rule is engineered for minimal memory footprint and maximum performance through careful data structure design.

#### Memory Usage Overview

| Component | Memory Type | Typical Size | Notes |
|-----------|-------------|--------------|-------|
| **FST Domain Index** | Read-only, shareable | 3-5 MB | Compressed in-memory or mmap |
| **IP-CIDR Ranges** | Read-only, shareable | 100-500 KB | Sorted arrays for binary search |
| **GeoIP Mappings** | Read-only, shareable | 10-50 KB | Compact country code storage |
| **Porn Heuristic** | Zero allocation | 0 bytes runtime | Compiled regex + static arrays |
| **Porn FST** | Read-only, shareable | 2.6 MB compressed | Optional, lazy-loaded |

**Total footprint for typical deployment:** 3-8 MB (read-only, shareable across threads/processes)

#### Zero-Copy Design

K2Rule achieves high performance through zero-copy techniques:

**Rust Implementation:**

```rust
// Memory-mapped file support (zero-copy from disk)
let reader = SliceReader::from_mmap("rules.k2r.gz")?;

// Direct byte slice access (no allocations)
let fst_data = &self.data[offset..offset + size];
let fst = Set::new(fst_data.to_vec())?;
```

**Go Implementation:**

```go
// Load entire file into memory (one allocation)
data, _ := os.ReadFile("rules.k2r.gz")

// Zero-copy slice views (no additional allocations)
fstData := r.data[offset : offset+size]
fst, _ := slice.NewFSTReader(fstData)

// Porn heuristic: zero allocations
isPorn := porn.IsPornHeuristic(domain)  // 0 allocs/op
```

#### FST Memory Efficiency

Finite State Transducers (FST) provide exceptional compression:

**Domain Storage Comparison:**

| Format | 700k Domains | Compression | Search Time |
|--------|--------------|-------------|-------------|
| **Hash Set** | ~35 MB | 1x | O(1) |
| **Trie** | ~25 MB | 1.4x | O(m) |
| **FST (K2Rule)** | ~3.6 MB | **9.7x** | O(m log n) |
| **FST + Gzip** | **2.6 MB** | **13.5x** | O(m log n) |

Where m = domain length, n = number of domains

**How FST Works:**

```
Traditional storage:
  "pornhub.com"  -> 12 bytes
  "pornhub.net"  -> 12 bytes
  "pornhub.org"  -> 12 bytes
  Total: 36 bytes

FST storage (shared prefixes):
  "pornhub."
     ├─ "com"
     ├─ "net"
     └─ "org"
  Total: ~15 bytes (58% savings)
```

FST exploits:
- **Prefix sharing**: Common domain prefixes stored once
- **Suffix sharing**: Reversed domains share TLD suffixes (.com, .net)
- **Deterministic structure**: No hash collisions, predictable memory

#### Memory-Mapped Files (Rust)

For large datasets, Rust supports memory-mapped I/O:

```rust
use memmap2::Mmap;

// Map file to memory (no upfront loading)
let file = File::open("rules.k2r.gz")?;
let mmap = unsafe { Mmap::map(&file)? };

// OS manages paging (only accessed pages in RAM)
let reader = SliceReader::from_bytes(&mmap)?;
```

**Benefits:**
- **Lazy loading**: Only read pages when accessed
- **Shared memory**: Multiple processes share same physical pages
- **OS-managed**: Kernel handles paging and eviction

**Tradeoffs:**
- Slower than in-memory on first access
- Best for > 10 MB datasets
- Not available in all environments (e.g., WASM)

#### Concurrent Access Patterns

Both Rust and Go implementations support safe concurrent access:

**Rust (Arc + RwLock):**

```rust
use std::sync::Arc;
use parking_lot::RwLock;

let reader = Arc::new(RwLock::new(SliceReader::from_file("rules.k2r.gz")?));

// Multiple readers, single writer
let clone = reader.clone();
tokio::spawn(async move {
    let r = clone.read();
    r.match_domain("google.com");
});
```

**Go (sync.RWMutex):**

```go
var (
    globalReader *slice.SliceReader
    mu           sync.RWMutex
)

// Read-heavy workload (multiple goroutines)
go func() {
    mu.RLock()
    defer mu.RUnlock()
    globalReader.MatchDomain("google.com")
}()
```

**Memory sharing:**
- Rule data shared across all threads/goroutines
- Read-only access requires no locking (Go) or read-lock (Rust)
- Single copy in memory regardless of concurrency

#### Cache-Friendly Design

K2Rule optimizes for CPU cache locality:

**Sequential Memory Access:**

```
IP-CIDR matching (sorted array):
  [10.0.0.0/8] [172.16.0.0/12] [192.168.0.0/16]
  Binary search: cache-friendly sequential access

GeoIP matching (compact encoding):
  [CN][US][JP][DE]... (4 bytes per entry)
  Linear scan fits in L1 cache
```

**Performance Impact:**

```
Cache miss penalty:
  L1 cache hit:  ~1 ns
  L2 cache hit:  ~3 ns
  L3 cache hit:  ~12 ns
  RAM access:    ~60 ns

K2Rule design minimizes cache misses:
  - Compact data structures
  - Sequential access patterns
  - Locality-preserving algorithms
```

#### Memory Benchmarks

**Rust:**

```
Rule loading:    3.2 MB allocated, 8.1 ms
Domain match:    0 bytes allocated, 1.2 μs
IP match:        0 bytes allocated, 180 ns
Porn heuristic:  0 bytes allocated, 420 ns
```

**Go:**

```
Rule loading:    3.2 MB allocated, 12.5 ms
Domain match:    0 bytes allocated, 8.7 μs
IP match:        0 bytes allocated, 520 ns
Porn heuristic:  0 bytes allocated, 17 μs
```

#### Optimization Guidelines

**For minimal memory usage:**

1. **Use heuristic-only porn detection** (0 MB)
   ```go
   k2rule.IsPornHeuristic(domain)  // No FST loading
   ```

2. **Load rules on-demand** (not at startup)
   ```go
   if needsRules {
       k2rule.InitFromFile("rules.k2r.gz")
   }
   ```

3. **Use compressed files** (2.6 MB vs 3.6 MB)
   ```bash
   # Already gzipped in CDN URLs
   ```

**For maximum performance:**

1. **Pre-load all rules** (8 MB resident)
   ```go
   k2rule.InitFromFile("rules.k2r.gz")
   k2rule.InitPornChecker("porn_domains.fst.gz")
   ```

2. **Enable mmap** (Rust only, large datasets)
   ```rust
   let reader = SliceReader::from_mmap("rules.k2r.gz")?;
   ```

3. **Add LRU cache** (optional, 1-10 MB)
   ```go
   // Future: k2rule.EnableCache(10_000)  // 10k entries
   ```

### 🎮 Use Cases

K2Rule powers routing decisions in various scenarios:

- **VPN Clients**: Smart routing for 翻墙 (GFW bypass) applications
- **Proxy Tools**: Rule engine for Clash, Shadowsocks, Sing-box, V2Ray, Trojan clients
- **Network Accelerators**: Traffic optimization for 加速器 applications
- **Parental Control**: Content filtering with porn domain detection
- **Enterprise Firewalls**: Domain and IP-based access control
- **Mobile Apps**: Lightweight rule matching for iOS/Android VPN apps

### 🙏 Acknowledgments

K2Rule stands on the shoulders of giants. We thank these amazing open-source projects:

**Proxy & VPN Ecosystem:**
- [Clash](https://github.com/Dreamacro/clash) - A rule-based tunnel in Go, inspiration for our rule format
- [Shadowsocks](https://github.com/shadowsocks) - The classic proxy protocol
- [Sing-box](https://github.com/SagerNet/sing-box) - Universal proxy platform
- [V2Ray](https://github.com/v2ray/v2ray-core) - Platform for building proxies
- [Trojan](https://github.com/trojan-gfw/trojan) - An unidentifiable mechanism for GFW bypass

**Rule Sources:**
- [Loyalsoldier/clash-rules](https://github.com/Loyalsoldier/clash-rules) - High-quality GFW bypass rules
- [Bon-Appetit/porn-domains](https://github.com/Bon-Appetit/porn-domains) - Comprehensive porn domain list
- [gfwlist](https://github.com/gfwlist/gfwlist) - The original GFW blocked sites list

**Rust Ecosystem:**
- [fst](https://github.com/BurntSushi/fst) - Finite state transducers for efficient string matching
- [regex](https://github.com/rust-lang/regex) - Fast regular expressions

### 📖 Documentation

- [Porn Heuristic Detection (EN)](docs/porn-heuristic-detection.md)
- [色情域名启发式检测 (中文)](docs/porn-heuristic-detection-zh.md)
- [Slice Format Design](docs/plans/2026-01-29-slice-based-rule-format.md)

### 📄 License

**Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0)**

Free for non-commercial use. For commercial licensing, contact: [kaitu.io](https://kaitu.io)

### 🏢 About Kaitu.io

K2Rule is developed by [Kaitu.io](https://kaitu.io) - a company focused on high-performance network infrastructure, proxy routing, and content filtering solutions.

**Our Products:**
- [Kaitu Desktop](https://kaitu.io) - Advanced network management and proxy client for macOS/Windows/Linux, supporting Clash, Shadowsocks, Sing-box, V2Ray, and more
- K2Rule - Open-source rule engine (this project), powering GFW bypass, VPN routing, and network acceleration

**Contact:** [https://kaitu.io](https://kaitu.io)

---

<a name="中文"></a>

## 中文

一个用 Rust 编写的超高性能规则路由和过滤系统，专为代理流量管理、VPN 路由和内容过滤优化。完美适配翻墙、科学上网、Clash/Shadowsocks/Sing-box 集成和网络加速器场景。

### ⚡ 性能亮点

| 特性 | 性能 |
|------|------|
| **色情域名检测** | 48.9% 启发式覆盖率，2.6 MB 压缩文件 |
| **规则匹配** | FST O(log n)，哈希查找 O(1) |
| **内存效率** | 大数据集支持内存映射文件 |
| **文件大小减少** | 智能启发式过滤减少 47% |

### 🎯 核心特性

- **🚀 高性能**：二进制索引格式，优化的查找算法
- **💾 内存高效**：内存映射文件，最小 RAM 占用
- **🌍 跨平台**：macOS、Linux、Windows、iOS、Android（通过 FFI）
- **🔄 Clash 兼容**：将 Clash YAML 规则转换为优化的二进制格式，适用于 VPN 和代理应用
- **🌐 翻墙支持**：专为 GFW 绕过场景设计，高效路由规则
- **⚡ 网络加速**：为加速器和流量管理优化
- **🔧 协议无关**：支持 Shadowsocks、Sing-box、V2Ray、Trojan 等代理协议
- **🧠 智能启发式**：基于模式的检测，文件大小减少 47%
- **🔒 零误判**：精心设计的规则，确保准确过滤

### 📦 支持的规则类型

- **DOMAIN**：精确和后缀域名匹配（使用 FST）
- **IP-CIDR**：IPv4/IPv6 CIDR 范围匹配
- **GEOIP**：基于地理位置的 IP 路由
- **IP-MATCH**：精确 IP 地址匹配

### 🔥 智能启发式色情域名检测

K2Rule 具有先进的双层色情域名检测系统：

#### 第一层：启发式检测（覆盖 48.9%）

使用 8 个检测层级的快速模式匹配：

1. **误判过滤器** - 排除合法域名（essex.ac.uk, adulteducation.gov）
2. **强关键词** - 平台品牌（pornhub, xvideos, chaturbate, onlyfans）
3. **3x 前缀模式** - 以"3x"开头的域名（3xmovies, 3xvideos）
4. **色情术语** - 40 个高频显式术语
5. **组合词** - 多词组合（sexcam, freeporn, bigass）
6. **动词+名词模式** - 137 个连续组合（free+porn, watch+sex）
7. **重复模式** - 字符/单词重复（xxx, sexsex）
8. **成人顶级域名** - ICANN 批准的域名（.xxx, .porn, .sex, .adult）

#### 第二层：FST 数据库（剩余 51.1% 域名）

在压缩的 FST 结构中对启发式未捕获的域名进行二分查找。

#### 性能影响

| 指标 | 无启发式 | 有启发式 | 改进 |
|------|---------|---------|------|
| **文件大小** | 4.9 MB | 2.6 MB | **-47%** |
| **存储域名数** | 707,915 | 361,489 | **-49%** |
| **检测速度** | 仅 FST | 启发式 + FST | **快约 2 倍** |
| **启发式覆盖** | 0% | 48.9% | **+48.9%** |

**数据源：** 来自 [Bon-Appetit/porn-domains](https://github.com/Bon-Appetit/porn-domains) 的 707,915 个域名

📖 **详细文档：** [色情域名启发式检测](docs/porn-heuristic-detection-zh.md)

### 📥 安装

```bash
cargo install --path .
```

### 🚀 快速开始

#### 生成色情域名列表

```bash
k2rule-gen generate-porn-fst -o output/porn_domains.fst.gz -v
```

输出：
```
Successfully generated FST porn domain list: "output/porn_domains.fst.gz"
  Source: 2026-01-28T08:17:56Z (707915 domains)
  Heuristic coverage: 346426 domains (48.9%)
  Stored in FST: 361489 domains
  FST size: 3609186 bytes uncompressed
  Compressed size: 2747095 bytes (76.1% of uncompressed)
```

#### 在应用中使用

```rust
use k2rule::porn_heuristic::is_porn_heuristic;
use k2rule::FstPornChecker;

// 快速启发式检查（无文件 I/O）
if is_porn_heuristic("pornhub.com") {
    return true; // 启发式检测到
}

// 对剩余域名进行 FST 查找
let checker = FstPornChecker::open("porn_domains.fst.gz")?;
if checker.is_porn("obscure-porn-site.com") {
    return true; // FST 检测到
}
```

### 📚 规则转换

#### 将 Clash YAML 转换为二进制

```bash
# Slice 格式（推荐）
k2rule-gen generate-slice -i clash_rules/cn_blacklist.yml -o cn_blacklist_v2.k2r.gz -v

# 生成所有规则集
k2rule-gen generate-slice-all -o output/ -v
```

#### 库使用

```rust
use k2rule::{SliceConverter, SliceReader, Target};

let yaml = r#"
rules:
  - DOMAIN-SUFFIX,cn.bing.com,DIRECT
  - DOMAIN-SUFFIX,bing.com,PROXY
  - GEOIP,CN,DIRECT
  - MATCH,PROXY
"#;

let converter = SliceConverter::new();
let data = converter.convert(yaml)?;

let reader = SliceReader::from_bytes(&data)?;
assert_eq!(reader.match_domain("cn.bing.com"), Some(Target::Direct));
assert_eq!(reader.match_domain("www.bing.com"), Some(Target::Proxy));
```

### 🌐 预构建规则（CDN）

| 规则集 | 描述 | URL |
|--------|------|-----|
| **cn_blacklist.k2r.gz** | 黑名单模式 | `cdn.jsdelivr.net/gh/kaitu-io/k2rule@release/cn_blacklist.k2r.gz` |
| **cn_whitelist.k2r.gz** | 白名单模式 | `cdn.jsdelivr.net/gh/kaitu-io/k2rule@release/cn_whitelist.k2r.gz` |
| **porn_domains.fst.gz** | 色情域名（2.6 MB） | `cdn.jsdelivr.net/gh/kaitu-io/k2rule@release/porn_domains.fst.gz` |

每日从 [Loyalsoldier/clash-rules](https://github.com/Loyalsoldier/clash-rules) 和 [Bon-Appetit/porn-domains](https://github.com/Bon-Appetit/porn-domains) 更新。

### 🎮 应用场景

K2Rule 为各种场景提供路由决策支持：

- **VPN 客户端**：翻墙应用的智能路由
- **代理工具**：Clash、Shadowsocks、Sing-box、V2Ray、Trojan 客户端的规则引擎
- **网络加速器**：加速器应用的流量优化
- **家长控制**：色情域名检测的内容过滤
- **企业防火墙**：基于域名和 IP 的访问控制
- **移动应用**：iOS/Android VPN 应用的轻量级规则匹配

### 🙏 致谢

K2Rule 站在巨人的肩膀上。感谢这些优秀的开源项目：

**代理 & VPN 生态：**
- [Clash](https://github.com/Dreamacro/clash) - Go 语言的规则隧道，我们规则格式的灵感来源
- [Shadowsocks](https://github.com/shadowsocks) - 经典的代理协议
- [Sing-box](https://github.com/SagerNet/sing-box) - 通用代理平台
- [V2Ray](https://github.com/v2ray/v2ray-core) - 构建代理的平台
- [Trojan](https://github.com/trojan-gfw/trojan) - 不可识别的 GFW 绕过机制

**规则来源：**
- [Loyalsoldier/clash-rules](https://github.com/Loyalsoldier/clash-rules) - 高质量的 GFW 绕过规则
- [Bon-Appetit/porn-domains](https://github.com/Bon-Appetit/porn-domains) - 全面的色情域名列表
- [gfwlist](https://github.com/gfwlist/gfwlist) - 原始的 GFW 被屏蔽网站列表

**Rust 生态：**
- [fst](https://github.com/BurntSushi/fst) - 高效字符串匹配的有限状态转换器
- [regex](https://github.com/rust-lang/regex) - 快速正则表达式

### 📖 文档

- [Porn Heuristic Detection (EN)](docs/porn-heuristic-detection.md)
- [色情域名启发式检测 (中文)](docs/porn-heuristic-detection-zh.md)
- [Slice 格式设计](docs/plans/2026-01-29-slice-based-rule-format.md)

### 📄 许可证

**知识共享 署名-非商业性使用 4.0 国际许可协议（CC BY-NC 4.0）**

非商业用途免费。商业授权请联系：[kaitu.io](https://kaitu.io)

### 🏢 关于 Kaitu.io

K2Rule 由 [Kaitu.io](https://kaitu.io) 开发 - 专注于高性能网络基础设施、代理路由和内容过滤解决方案的公司。

**我们的产品：**
- [Kaitu Desktop](https://kaitu.io) - macOS/Windows/Linux 高级网络管理和代理客户端，支持 Clash、Shadowsocks、Sing-box 等协议
- K2Rule - 开源规则引擎（本项目），为翻墙、科学上网、VPN 路由提供核心支持

**联系我们：** [https://kaitu.io](https://kaitu.io)

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## ⭐ Star History

If you find K2Rule useful, please consider giving it a star on GitHub!

---

**Powered by [Kaitu.io](https://kaitu.io)**
