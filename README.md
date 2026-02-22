# K2Rule - High-Performance Rule Engine for Go

[English](#english) | [中文](#中文)

---

<a name="english"></a>

## English

A high-performance rule-based routing and filtering engine written in Go, optimized for proxy traffic management, VPN routing, and content filtering. Perfect for GFW bypass, Clash/Shadowsocks/Sing-box integration, and network acceleration solutions.

## Quick Start

### Installation

```bash
go get github.com/kaitu-io/k2rule
```

### 3-Line Integration

```go
config := &k2rule.Config{
    RuleURL:  "https://cdn.jsdelivr.net/gh/kaitu-io/k2rule@release/cn_blacklist.k2r.gz",
    CacheDir: "/tmp/k2rule",  // REQUIRED: caller must provide writable directory
}
k2rule.Init(config)

target := k2rule.Match("google.com")  // Returns PROXY
```

The fallback target (DIRECT, PROXY, or REJECT) is automatically read from the .k2r file header, which comes from the Clash YAML's `MATCH` rule.

### Choose Your Rule Mode

| Mode | Default Behavior | Use Case | CDN URL |
|------|------------------|----------|---------|
| **Blacklist (Recommended)** | Default DIRECT | China users, mainly domestic content | [`cn_blacklist.k2r.gz`](https://cdn.jsdelivr.net/gh/kaitu-io/k2rule@release/cn_blacklist.k2r.gz) |
| Whitelist | Default PROXY | International access priority | [`cn_whitelist.k2r.gz`](https://cdn.jsdelivr.net/gh/kaitu-io/k2rule@release/cn_whitelist.k2r.gz) |

- **Blacklist**: Unknown domain -> DIRECT, GFW sites -> PROXY
- **Whitelist**: Unknown domain -> PROXY, China IP -> DIRECT

Different URLs use separate cache files. Switch anytime without conflicts.

### Complete Example

```go
package main

import (
    "fmt"
    "github.com/kaitu-io/k2rule"
)

func main() {
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

### iOS / Platform CacheDir

CacheDir is **required** on all platforms. Use a platform-appropriate writable directory:

```go
// macOS app:    ~/Library/Caches/com.kaitu.app/k2rule
// macOS daemon: /var/tmp/k2rule
// iOS:          NSCachesDirectory (from Swift bridge) — NOT Documents/ (iCloud sync)
// Android:      context.getCacheDir() (from JNI)
// Linux:        /var/cache/k2rule
// Windows:      %LocalAppData%\k2rule\cache
```

### Cache & Update Mechanism

Each rule URL uses a separate cache file (based on URL's SHA256 hash):

```
{CacheDir}/
├── abcd1234.k2r.gz  <- cn_blacklist
├── 5678efgh.k2r.gz  <- cn_whitelist
└── abcd1234.mmdb    <- GeoIP database
```

- **Download retry**: Infinite retry with exponential backoff (1s -> 2s -> ... -> 64s cap)
- **Init()** blocks until all resources are available
- **Auto-update**: Background checks every 6 hours, ETag-based (304 skips download), zero-downtime hot reload

### Binary Format: K2RULEV3

K2Rule uses a custom binary format for fast rule matching:

```
HEADER (64B):  Magic("K2RULEV3") + Version + SliceCount + FallbackTarget + Timestamp + Checksum
SLICE INDEX:   SliceType(1B) + Target(1B) + Offset(4B) + Size(4B) + Count(4B)  x N
SLICE DATA:    SortedDomain | CidrV4 | CidrV6 | GeoIP (variable)
```

Domain encoding: lowercase -> dot-prefix -> reverse -> sort -> binary search.
Distributed as `.k2r.gz`. The mmap reader decompresses to a SHA256-named temp file.

See [docs/knowledge/architecture-overview.md](docs/knowledge/architecture-overview.md) for detailed format spec.

### Supported Rule Types

| Type | Description |
|------|-------------|
| `DOMAIN` / `DOMAIN-SUFFIX` | Exact and suffix domain matching via sorted binary search |
| `IP-CIDR` | IPv4 CIDR range matching |
| `IP-CIDR6` | IPv6 CIDR range matching |
| `GEOIP` | Geographic IP-based routing (MaxMind GeoLite2) |
| `RULE-SET` | Clash rule provider expansion (domain, ipcidr, classical) |
| `MATCH` | Fallback target (stored in file header) |

### Porn Domain Detection

Two-layer detection system with smart heuristics:

- **Layer 1: Heuristic** — 8-layer pattern matching (keywords, compounds, verb+noun, TLDs), covers ~47% of known porn domains. Zero I/O, zero allocations.
- **Layer 2: K2RULEV3 Sorted Domain Database** — binary search for remaining domains not caught by heuristics.

| Metric | Value |
|--------|-------|
| **Source domains** | ~717K from [Bon-Appetit/porn-domains](https://github.com/Bon-Appetit/porn-domains) |
| **Heuristic coverage** | ~338K domains (~47%) |
| **Stored in K2RULEV3** | ~380K domains |
| **Compressed size** | ~3.1 MB |

Detailed documentation: [Porn Heuristic Detection](docs/porn-heuristic-detection.md) | [中文](docs/porn-heuristic-detection-zh.md)

### Generator CLI

```bash
# Generate all rule files from Clash YAML configs
go run ./cmd/k2rule-gen generate-all -o output/ -v

# Generate porn domain list
go run ./cmd/k2rule-gen generate-porn -o output/porn_domains.k2r.gz -v
```

`generate-all` reads `clash_rules/*.yml`, downloads rule-providers, converts to K2RULEV3, and gzip-writes.
`generate-porn` fetches the Bon-Appetit blocklist, filters heuristic-detectable domains, writes K2RULEV3 with target=Reject.

### Pre-built Rules (CDN)

| Rule Set | Description | URL |
|----------|-------------|-----|
| **cn_blacklist.k2r.gz** | Blacklist mode | `cdn.jsdelivr.net/gh/kaitu-io/k2rule@release/cn_blacklist.k2r.gz` |
| **cn_whitelist.k2r.gz** | Whitelist mode | `cdn.jsdelivr.net/gh/kaitu-io/k2rule@release/cn_whitelist.k2r.gz` |
| **porn_domains.k2r.gz** | Porn domains (~3.1 MB) | `cdn.jsdelivr.net/gh/kaitu-io/k2rule@release/porn_domains.k2r.gz` |

Updated daily from [Loyalsoldier/clash-rules](https://github.com/Loyalsoldier/clash-rules) and [Bon-Appetit/porn-domains](https://github.com/Bon-Appetit/porn-domains).

### API Reference

#### Configuration

```go
type Config struct {
    RuleURL  string  // Remote rule file URL ("" = no remote rules)
    RuleFile string  // Local rule file path

    GeoIPURL  string  // "" = default MaxMind GeoLite2
    GeoIPFile string  // Local .mmdb file path

    PornURL  string  // "" = default CDN
    PornFile string  // Local .k2r.gz file path

    CacheDir string  // REQUIRED: writable directory for downloads

    IsGlobal     bool    // true = global proxy mode
    GlobalTarget Target  // Target for global mode (default: TargetProxy)
}
```

#### Core Functions

```go
func Init(config *Config) error           // Initialize (the only init method)
func Match(input string) Target           // Route domain or IP -> Target
func IsPorn(domain string) bool           // Heuristic + K2RULEV3 lookup
func IsPornHeuristic(domain string) bool  // Heuristic only (no I/O)
func ToggleGlobal(enabled bool)           // Switch global mode on/off
func SetGlobalTarget(target Target)       // Change global target at runtime
```

#### Targets

```go
const (
    TargetDirect Target = 0  // Direct connection
    TargetProxy  Target = 1  // Proxy connection
    TargetReject Target = 2  // Reject/block
)
```

#### Match Priority

1. LAN/Private IPs -> DIRECT (always, hardcoded)
2. TmpRule exact match (per-connection override)
3. Global mode -> GlobalTarget
4. IP-CIDR rules
5. GeoIP rules
6. Domain rules
7. Fallback from file header

### Performance

| Feature | Performance |
|---------|-------------|
| Domain matching | O(log n) sorted binary search, 0 allocs |
| IP-CIDR matching | O(log n) binary search, 0 allocs |
| Porn heuristic | 0 allocs, ~17 us/op |
| Memory (rules) | ~200 KB mmap'd, shared across processes |
| Memory (GeoIP) | ~10 MB mmap'd |
| Hot reload | Zero-downtime via atomic swap |

### Use Cases

- **VPN Clients**: Smart routing for GFW bypass applications
- **Proxy Tools**: Rule engine for Clash, Shadowsocks, Sing-box, V2Ray, Trojan
- **Network Accelerators**: Traffic optimization
- **Parental Control**: Content filtering with porn domain detection
- **Enterprise Firewalls**: Domain and IP-based access control
- **Mobile Apps**: Lightweight rule matching for iOS/Android VPN apps

### Acknowledgments

**Proxy & VPN Ecosystem:**
- [Clash](https://github.com/Dreamacro/clash) — rule-based tunnel in Go, inspiration for our rule format
- [Shadowsocks](https://github.com/shadowsocks), [Sing-box](https://github.com/SagerNet/sing-box), [V2Ray](https://github.com/v2ray/v2ray-core), [Trojan](https://github.com/trojan-gfw/trojan)

**Rule Sources:**
- [Loyalsoldier/clash-rules](https://github.com/Loyalsoldier/clash-rules) — high-quality GFW bypass rules
- [Bon-Appetit/porn-domains](https://github.com/Bon-Appetit/porn-domains) — comprehensive porn domain list
- [gfwlist](https://github.com/gfwlist/gfwlist)

**Go Libraries:**
- [mmap-go](https://github.com/edsrzf/mmap-go) — cross-platform memory-mapped files
- [geoip2-golang](https://github.com/oschwald/geoip2-golang) — MaxMind GeoIP2 reader

### Documentation

- [Porn Heuristic Detection (EN)](docs/porn-heuristic-detection.md)
- [色情域名启发式检测 (中文)](docs/porn-heuristic-detection-zh.md)

### License

**Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0)**

Free for non-commercial use. For commercial licensing, contact: [kaitu.io](https://kaitu.io)

### About Kaitu.io

K2Rule is developed by [Kaitu.io](https://kaitu.io) — high-performance network infrastructure, proxy routing, and content filtering.

- [Kaitu Desktop](https://kaitu.io) — advanced proxy client for macOS/Windows/Linux, supporting Clash, Shadowsocks, Sing-box, V2Ray
- K2Rule — open-source rule engine (this project)

---

<a name="中文"></a>

## 中文

一个用 Go 编写的高性能规则路由和过滤引擎，专为代理流量管理、VPN 路由和内容过滤优化。完美适配翻墙、科学上网、Clash/Shadowsocks/Sing-box 集成和网络加速器场景。

### 快速开始

```bash
go get github.com/kaitu-io/k2rule
```

```go
config := &k2rule.Config{
    RuleURL:  "https://cdn.jsdelivr.net/gh/kaitu-io/k2rule@release/cn_blacklist.k2r.gz",
    CacheDir: "/tmp/k2rule",  // 必需：调用方提供可写目录
}
k2rule.Init(config)

target := k2rule.Match("google.com")  // 返回 PROXY
```

### 选择规则模式

| 模式 | 默认行为 | 适用场景 | CDN URL |
|------|---------|---------|---------|
| **黑名单（推荐）** | 默认 DIRECT | 中国用户，以国内内容为主 | [`cn_blacklist.k2r.gz`](https://cdn.jsdelivr.net/gh/kaitu-io/k2rule@release/cn_blacklist.k2r.gz) |
| 白名单 | 默认 PROXY | 国际访问优先 | [`cn_whitelist.k2r.gz`](https://cdn.jsdelivr.net/gh/kaitu-io/k2rule@release/cn_whitelist.k2r.gz) |

### 核心特性

- **高性能**：K2RULEV3 二进制格式，排序二分查找
- **内存高效**：内存映射文件，~200 KB 常驻内存
- **跨平台**：macOS、Linux、Windows、iOS、Android
- **Clash 兼容**：Clash YAML 规则转换为优化的二进制格式
- **翻墙支持**：专为 GFW 绕过场景设计
- **网络加速**：为加速器和流量管理优化
- **协议无关**：支持 Shadowsocks、Sing-box、V2Ray、Trojan 等代理协议
- **智能启发式**：色情域名检测减少 ~47% 文件大小
- **零停机热重载**：后台自动更新规则

### 支持的规则类型

| 类型 | 描述 |
|------|------|
| `DOMAIN` / `DOMAIN-SUFFIX` | 精确和后缀域名匹配（排序二分查找） |
| `IP-CIDR` / `IP-CIDR6` | IPv4/IPv6 CIDR 范围匹配 |
| `GEOIP` | 基于地理位置的 IP 路由 |
| `RULE-SET` | Clash 规则提供者展开 |
| `MATCH` | 兜底目标（存储在文件头） |

### 色情域名检测

双层检测系统：

- **第一层：启发式检测** — 8 层模式匹配，覆盖约 47% 已知色情域名，零 I/O
- **第二层：K2RULEV3 排序域名数据库** — 对启发式未捕获的域名进行二分查找

| 指标 | 数值 |
|------|------|
| **源域名数** | ~717K（来自 [Bon-Appetit/porn-domains](https://github.com/Bon-Appetit/porn-domains)） |
| **启发式覆盖** | ~338K 域名（~47%） |
| **K2RULEV3 存储** | ~380K 域名 |
| **压缩大小** | ~3.1 MB |

详细文档：[色情域名启发式检测](docs/porn-heuristic-detection-zh.md) | [English](docs/porn-heuristic-detection.md)

### 生成器 CLI

```bash
# 从 Clash YAML 配置生成所有规则文件
go run ./cmd/k2rule-gen generate-all -o output/ -v

# 生成色情域名列表
go run ./cmd/k2rule-gen generate-porn -o output/porn_domains.k2r.gz -v
```

### 预构建规则（CDN）

| 规则集 | 描述 | URL |
|--------|------|-----|
| **cn_blacklist.k2r.gz** | 黑名单模式 | `cdn.jsdelivr.net/gh/kaitu-io/k2rule@release/cn_blacklist.k2r.gz` |
| **cn_whitelist.k2r.gz** | 白名单模式 | `cdn.jsdelivr.net/gh/kaitu-io/k2rule@release/cn_whitelist.k2r.gz` |
| **porn_domains.k2r.gz** | 色情域名（~3.1 MB） | `cdn.jsdelivr.net/gh/kaitu-io/k2rule@release/porn_domains.k2r.gz` |

每日从 [Loyalsoldier/clash-rules](https://github.com/Loyalsoldier/clash-rules) 和 [Bon-Appetit/porn-domains](https://github.com/Bon-Appetit/porn-domains) 更新。

### API 参考

```go
func Init(config *Config) error           // 初始化（唯一入口）
func Match(input string) Target           // 路由域名或 IP -> Target
func IsPorn(domain string) bool           // 启发式 + K2RULEV3 查找
func IsPornHeuristic(domain string) bool  // 仅启发式（无 I/O）
func ToggleGlobal(enabled bool)           // 切换全局代理模式
```

### 匹配优先级

1. LAN/私有 IP -> DIRECT（始终，硬编码）
2. TmpRule 精确匹配（每连接覆盖）
3. 全局模式 -> GlobalTarget
4. IP-CIDR 规则
5. GeoIP 规则
6. 域名规则
7. 文件头兜底

### 应用场景

- **VPN 客户端**：翻墙应用的智能路由
- **代理工具**：Clash、Shadowsocks、Sing-box、V2Ray、Trojan 客户端的规则引擎
- **网络加速器**：加速器应用的流量优化
- **家长控制**：色情域名检测的内容过滤
- **企业防火墙**：基于域名和 IP 的访问控制
- **移动应用**：iOS/Android VPN 应用的轻量级规则匹配

### 致谢

**代理 & VPN 生态：**
- [Clash](https://github.com/Dreamacro/clash)、[Shadowsocks](https://github.com/shadowsocks)、[Sing-box](https://github.com/SagerNet/sing-box)、[V2Ray](https://github.com/v2ray/v2ray-core)、[Trojan](https://github.com/trojan-gfw/trojan)

**规则来源：**
- [Loyalsoldier/clash-rules](https://github.com/Loyalsoldier/clash-rules)、[Bon-Appetit/porn-domains](https://github.com/Bon-Appetit/porn-domains)、[gfwlist](https://github.com/gfwlist/gfwlist)

**Go 库：**
- [mmap-go](https://github.com/edsrzf/mmap-go)、[geoip2-golang](https://github.com/oschwald/geoip2-golang)

### 文档

- [Porn Heuristic Detection (EN)](docs/porn-heuristic-detection.md)
- [色情域名启发式检测 (中文)](docs/porn-heuristic-detection-zh.md)

### 许可证

**知识共享 署名-非商业性使用 4.0 国际许可协议（CC BY-NC 4.0）**

非商业用途免费。商业授权请联系：[kaitu.io](https://kaitu.io)

### 关于 Kaitu.io

K2Rule 由 [Kaitu.io](https://kaitu.io) 开发 — 高性能网络基础设施、代理路由和内容过滤。

- [Kaitu Desktop](https://kaitu.io) — macOS/Windows/Linux 高级代理客户端
- K2Rule — 开源规则引擎（本项目）

---

**Powered by [Kaitu.io](https://kaitu.io)**
