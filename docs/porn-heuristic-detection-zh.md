# 色情域名启发式检测

快速的、基于模式的色情域名检测，覆盖率达 **~47%**，零误判。

## 概述

K2Rule 使用智能启发式模式在查询 K2RULEV3 排序域名数据库之前检测色情域名。这种双层方法显著减少了文件大小并提升了性能：

- **第一层：启发式检测** — 快速模式匹配（覆盖约 47% 的域名）
- **第二层：K2RULEV3 排序域名查找** — 排序域名数据库中的二分查找（覆盖剩余约 53%）

## 性能影响

| 指标 | 无启发式 | 有启发式 | 改进 |
|------|---------|---------|------|
| **总域名数** | ~717K | ~717K | - |
| **启发式覆盖** | 0 (0%) | ~338K (~47%) | +47% |
| **K2RULEV3 存储** | ~717K | ~380K | -47% |
| **文件大小（压缩）** | ~5.8 MB | ~3.1 MB | **-47%** |
| **检测速度** | 仅 K2RULEV3 | 启发式 + K2RULEV3 | **快约 2 倍** |

## 检测层级

启发式引擎使用 8 个检测层级，按优先级顺序检查：

### 1. 误判过滤器

排除包含色情相关关键词的合法域名：

```
// 英国地区：essex, middlesex, sussex, wessex
essex.ac.uk        -> 非色情
middlesex.edu      -> 非色情

// 成人教育
adulteducation.gov -> 非色情
adultlearning.org  -> 非色情

// 技术
macosx.apple.com   -> 非色情
```

### 2. 强关键词

平台品牌和明确的术语（20 个关键词）：

```
porn, pornhub, xvideos, xnxx, hentai, redtube, youporn
chaturbate, onlyfans, livejasmin, bongacams, stripchat
...
```

**示例：**
- `pornhub.com` -> 检测到
- `xvideos.net` -> 检测到
- `chaturbate.tv` -> 检测到

### 3. 特殊正则模式：3x 前缀

匹配以"3x"开头的域名：

```regex
^3x
```

**示例：**
- `3xmovies.com` -> 检测到
- `3xvideos.net` -> 检测到
- `some3x.com` -> 未检测到（3x 不在开头）

### 4. 色情术语

40 个高频显式术语（每个出现 500+ 次）：

**身体部位：** pussy, cock, dick, tits, boobs
**活动：** fuck, fucking, anal, gangbang, blowjob
**类型：** bdsm, fetish, bondage, hardcore
**人口统计：** milf, teen, amateur, asian, ebony
**性取向：** gay, lesbian, shemale
**描述性：** nude, naked, dirty, sexy, erotic
**多语言：** porno, sexe, jav

### 5. 组合词

27 个多词组合（安全组合）：

```
sexcam, freeporn, livesex, porntube, xxxporn
sextube, hotsex, sexporn, pornsite, freesex
bigass, phatass, niceass  <- 安全的 "ass" 组合
```

**为什么使用组合词？**
- 单独的 `tube` 会匹配 `youtube.com`（误判）
- `porntube` 只匹配色情网站

### 6. 动词+名词模式

137 个连续词组合，支持 3 种匹配模式：

**模式示例：**
- `free + porn`（1,955 次出现）
- `live + sex`（1,787 次出现）
- `cam + girl`（1,434 次出现）

**匹配模式：**
1. **直接连接：** `freeporn.com`
2. **分隔符：** `free-porn.net`, `free_porn.tv`
3. **填充词：** `freegirlporn.com`（词间 <=4 个字符）

### 7. 重复模式

字符和单词重复：

- `xxx` -> `xxxvideos.com`
- `sexsex` -> `sexsex.com`
- `camcam` -> `camcam.tv`

### 8. 成人顶级域名

ICANN 批准的成人内容域名：

```
.xxx    (2011 年批准)
.adult  (2014 年批准)
.porn   (2014 年批准)
.sex    (2015 年批准)
```

## 覆盖率统计

基于对 **~717K 个色情域名**的分析：

| 检测层级 | 增量覆盖 | 累积覆盖 |
|---------|---------|---------|
| 关键词 | ~38% | 38% |
| + 术语 | +16% | 54% |
| + 组合词 | +3% | 57% |
| + 动词+名词 | ~0% | 57% |
| + 特殊模式 | +0.3% | **57.3%** |

**注意：** 实际过滤达到 **~47% 覆盖率**，因为优化了去重。

## 防止误判

通过以下方式实现零误判：

1. **排除列表**
   - 常见单词：class, glass, pass, grass, mass, bass, brass
   - 英国地区：essex, middlesex, sussex, wessex
   - 合法服务：成人教育、youtube

2. **仅组合匹配**
   - `tube` -> 仅在 `porntube`、`sextube` 中
   - `ass` -> 仅在 `bigass`、`phatass`、`niceass` 中

3. **上下文感知模式**
   - `3x` -> 仅匹配 `^3x`（前缀）
   - 已删除：69 模式（在日期/版本中误判太多）

## 使用示例

```go
import "github.com/kaitu-io/k2rule/internal/porn"

// 关键词
porn.IsPornHeuristic("pornhub.com")    // true
porn.IsPornHeuristic("example.xxx")    // true

// 术语
porn.IsPornHeuristic("pussy.com")      // true
porn.IsPornHeuristic("milf-videos.net") // true

// 组合词
porn.IsPornHeuristic("freeporn.tv")    // true
porn.IsPornHeuristic("bigass.com")     // true

// 动词+名词模式
porn.IsPornHeuristic("watch-porn.com") // true

// 无误判
porn.IsPornHeuristic("google.com")     // false
porn.IsPornHeuristic("class.com")      // false
porn.IsPornHeuristic("essex.ac.uk")    // false
```

## 与 K2RULEV3 集成

启发式在两个场景中工作：

### 1. 文件生成（构建时）

在写入 K2RULEV3 前过滤域名：

```go
// 在 cmd/k2rule-gen generate-porn 中
var stored []string
for _, domain := range allDomains {
    if !porn.IsPornHeuristic(domain) {
        stored = append(stored, domain)
    }
}
// 将 stored 域名写入 K2RULEV3，target=Reject
```

**结果：** ~5.8 MB -> ~3.1 MB（-47% 大小减少）

### 2. 运行时检测

K2RULEV3 查找前的第一道过滤：

```go
func (c *PornChecker) IsPorn(domain string) bool {
    // 快速启发式检查（无文件 I/O）
    if porn.IsPornHeuristic(domain) {
        return true
    }
    // 对剩余域名进行 K2RULEV3 排序域名查找
    if c.reader != nil {
        if target := c.reader.MatchDomain(domain); target != nil {
            return *target == 2 // targetReject
        }
    }
    return false
}
```

**结果：** 启发式匹配的域名快约 2 倍

## 维护

### 添加新关键词

编辑 `internal/porn/data.go`：

```go
var strongKeywords = []string{
    "porn",
    "xvideos",
    "yournewkeyword",  // 在此添加
}
```

### 添加组合词

```go
var compoundTerms = []string{
    "sexcam",
    "freeporn",
    "yournewcompound",  // 在此添加
}
```

### 测试

```bash
go test ./internal/porn/...
```

## 性能考虑

- **模式编译：** 所有模式在初始化时编译一次
- **内存开销：** 所有模式约 100 KB
- **运行时开销：** 相比仅 K2RULEV3 方式 <10%
- **文件大小收益：** 减少约 47%

## 相关文档

- [English Documentation](./porn-heuristic-detection.md) — 英文版本
- [实现代码](../internal/porn/heuristic.go) — 源代码
- [README](../README.md) — 项目概述

---

**Powered by [Kaitu.io](https://kaitu.io) — Go 高性能规则引擎**
