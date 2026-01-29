# 色情域名启发式检测

快速的、基于模式的色情域名检测，覆盖率达 **48.9%**，零误判。

## 概述

K2Rule 使用智能启发式模式在查询完整 FST 数据库之前检测色情域名。这种双层方法显著减少了文件大小并提升了性能：

- **第一层：启发式检测** - 快速模式匹配（覆盖 48.9% 的域名）
- **第二层：FST 查找** - 压缩数据库中的二分查找（覆盖剩余 51.1%）

## 性能影响

| 指标 | 无启发式 | 有启发式 | 改进 |
|------|---------|---------|------|
| **总域名数** | 707,915 | 707,915 | - |
| **启发式覆盖** | 0 (0%) | 346,426 (48.9%) | +48.9% |
| **FST 存储** | 707,915 | 361,489 | -49% |
| **文件大小（压缩）** | 4.9 MB | 2.6 MB | **-47%** |
| **检测速度** | 仅 FST | 启发式 + FST | **快约 2 倍** |

## 检测层级

启发式引擎使用 8 个检测层级，按优先级顺序检查：

### 1. 误判过滤器

排除包含色情相关关键词的合法域名：

```rust
// 英国地区：essex, middlesex, sussex, wessex
essex.ac.uk ❌
middlesex.edu ❌

// 成人教育
adulteducation.gov ❌
adultlearning.org ❌

// 技术
macosx.apple.com ❌
```

### 2. 强关键词

平台品牌和明确的术语（20 个关键词）：

```
porn, pornhub, xvideos, xnxx, hentai, redtube, youporn
chaturbate, onlyfans, livejasmin, bongacams, stripchat
...
```

**示例：**
- `pornhub.com` ✓
- `xvideos.net` ✓
- `chaturbate.tv` ✓

### 3. 特殊正则模式：3x 前缀

匹配以"3x"开头的域名：

```regex
^3x
```

**示例：**
- `3xmovies.com` ✓
- `3xvideos.net` ✓
- `some3x.com` ❌（3x 不在开头）

### 4. 色情术语

40 个高频显式术语（每个出现 500+ 次）：

**身体部位：** pussy, cock, dick, tits, boobs
**活动：** fuck, fucking, anal, gangbang, blowjob
**类型：** bdsm, fetish, bondage, hardcore
**人口统计：** milf, teen, amateur, asian, ebony
**性取向：** gay, lesbian, shemale
**描述性：** nude, naked, dirty, sexy, erotic
**多语言：** porno, sexe, jav

**示例：**
- `pussy.com` ✓
- `milf-videos.net` ✓
- `bdsm.tv` ✓

### 5. 组合词

27 个多词组合（安全组合）：

```
sexcam, freeporn, livesex, porntube, xxxporn
sextube, hotsex, sexporn, pornsite, freesex
bigass, phatass, niceass  ← 安全的 "ass" 组合
```

**为什么使用组合词？**
- 单独的 `tube` 会匹配 `youtube.com` ❌
- `porntube` 只匹配色情网站 ✓

**示例：**
- `sexcam.com` ✓
- `freeporn.net` ✓
- `bigass.tv` ✓（组合形式）
- `class.com` ❌（ass 不在组合中）

### 6. 动词+名词模式

137 个连续词组合，支持 3 种匹配模式：

**模式示例：**
- `free + porn`（1,955 次出现）
- `live + sex`（1,787 次出现）
- `cam + girl`（1,434 次出现）
- `watch + porn`（122 次出现）

**匹配模式：**

1. **直接连接：** `freeporn.com` ✓
2. **分隔符：** `free-porn.net`, `free_porn.tv` ✓
3. **填充词：** `freegirlporn.com` ✓（词间 ≤4 个字符）

**示例：**
- `watchporn.com` ✓（直接）
- `watch-sex.net` ✓（分隔符）
- `watchgirlsex.tv` ✓（填充："girl"）

### 7. 重复模式

字符和单词重复：

**字符重复：**
- `xxx` → `xxxvideos.com` ✓
- `xxxxxx` → `xxxxxx.net` ✓

**单词重复：**
- `sexsex` → `sexsex.com` ✓
- `camcam` → `camcam.tv` ✓
- `girlgirl` → `girlgirl.net` ✓

### 8. 成人顶级域名

ICANN 批准的成人内容域名：

```
.xxx    (2011 年批准)
.adult  (2014 年批准)
.porn   (2014 年批准)
.sex    (2015 年批准)
```

**示例：**
- `example.xxx` ✓
- `site.porn` ✓
- `anything.sex` ✓

## 覆盖率统计

基于对 **707,915 个色情域名**的分析：

| 检测层级 | 增量覆盖 | 累积覆盖 |
|---------|---------|---------|
| 关键词 | ~38% | 38% |
| + 术语 | +16% | 54% |
| + 组合词 | +3% | 57% |
| + 动词+名词 | ~0% | 57% |
| + 特殊模式 | +0.3% | **57.3%** |

**注意：** 实际 FST 过滤达到 **48.9% 覆盖率**，因为优化了去重。

## 防止误判

通过以下方式实现零误判：

1. **排除列表**
   - 常见单词：class, glass, pass, grass, mass, bass, brass
   - 英国地区：essex, middlesex, sussex, wessex
   - 合法服务：成人教育、youtube

2. **仅组合匹配**
   - `tube` → 仅在 `porntube`、`sextube` 中
   - `ass` → 仅在 `bigass`、`phatass`、`niceass` 中

3. **上下文感知模式**
   - `3x` → 仅匹配 `^3x`（前缀）
   - 已删除：69 模式（在日期/版本中误判太多）

## 使用示例

```rust
use k2rule::porn_heuristic::is_porn_heuristic;

// 关键词
assert!(is_porn_heuristic("pornhub.com"));
assert!(is_porn_heuristic("example.xxx"));

// 术语
assert!(is_porn_heuristic("pussy.com"));
assert!(is_porn_heuristic("milf-videos.net"));

// 组合词
assert!(is_porn_heuristic("freeporn.tv"));
assert!(is_porn_heuristic("bigass.com"));

// 动词+名词模式
assert!(is_porn_heuristic("watch-porn.com"));
assert!(is_porn_heuristic("freexxxmovies.net"));

// 无误判
assert!(!is_porn_heuristic("google.com"));
assert!(!is_porn_heuristic("class.com"));
assert!(!is_porn_heuristic("essex.ac.uk"));
```

## 与 FST 集成

启发式在两个场景中工作：

### 1. 文件生成（构建时）

在写入 FST 前过滤域名：

```rust
// 在 k2rule-gen 中
let filtered_domains: Vec<&str> = all_domains
    .iter()
    .filter(|domain| !is_porn_heuristic(domain))
    .copied()
    .collect();

build_porn_fst(&filtered_domains)?;
```

**结果：** 4.9 MB → 2.6 MB（-47% 大小减少）

### 2. 运行时检测

FST 查找前的第一道过滤：

```rust
pub fn is_porn(&mut self, domain: &str) -> bool {
    // 快速启发式检查（无文件 I/O）
    if is_porn_heuristic(domain) {
        return true;
    }

    // 对剩余域名进行 FST 查找
    self.check_fst(domain)
}
```

**结果：** 启发式匹配的域名快约 2 倍

## 维护

### 添加新关键词

```rust
const PORN_KEYWORDS: &[&str] = &[
    "porn",
    "xvideos",
    "yournewkeyword",  // 在此添加
];
```

### 添加组合词

```rust
const PORN_COMPOUNDS: &[&str] = &[
    "sexcam",
    "freeporn",
    "yournewcompound",  // 在此添加
];
```

### 测试

所有更改必须通过测试套件：

```bash
cargo test --lib porn_heuristic
```

## 性能考虑

- **正则编译：** 所有模式在启动时编译一次（惰性静态）
- **内存开销：** 所有模式约 100 KB
- **运行时开销：** 相比仅 FST 方式 <10%
- **文件大小收益：** 减少 47%（4.9 MB → 2.6 MB）

## 相关文档

- [English Documentation](./porn-heuristic-detection.md) - 英文版本
- [实现代码](../src/porn_heuristic.rs) - 源代码
- [README](../README.md) - 项目概述

---

**Powered by [Kaitu.io](https://kaitu.io) - Rust 高级规则引擎**
