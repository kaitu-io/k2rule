// Package main implements the k2rule-gen CLI tool for generating K2RULEV2 binary rule files.
//
// Usage:
//
//	k2rule-gen generate-all -o output/ [-v]
//	k2rule-gen generate-porn -o output/porn_domains.k2r.gz [-v]
package main

import (
	"compress/gzip"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: k2rule-gen <command> [flags]\n")
		fmt.Fprintf(os.Stderr, "Commands:\n")
		fmt.Fprintf(os.Stderr, "  generate-all   Generate all rule sets from clash_rules/ directory\n")
		fmt.Fprintf(os.Stderr, "  generate-porn  Generate porn domain blocklist\n")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "generate-all":
		runGenerateAll(os.Args[2:])
	case "generate-porn":
		runGeneratePorn(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", os.Args[1])
		os.Exit(1)
	}
}

// runGenerateAll implements the generate-all subcommand.
func runGenerateAll(args []string) {
	fs := flag.NewFlagSet("generate-all", flag.ExitOnError)
	outputDir := fs.String("o", "output", "Output directory for binary files")
	verbose := fs.Bool("v", false, "Verbose output")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if *verbose {
		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug})))
	}

	if err := os.MkdirAll(*outputDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating output directory: %v\n", err)
		os.Exit(1)
	}

	clashRulesDir := "clash_rules"
	if _, err := os.Stat(clashRulesDir); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "Error: clash_rules directory not found\n")
		os.Exit(1)
	}

	// Generate cn_blacklist.k2r.gz
	blacklistPath := filepath.Join(clashRulesDir, "cn_blacklist.yml")
	if _, err := os.Stat(blacklistPath); err == nil {
		outputPath := filepath.Join(*outputDir, "cn_blacklist.k2r.gz")
		slog.Info("generating blacklist", "input", blacklistPath, "output", outputPath)
		if err := convertClashYAML(blacklistPath, outputPath, *verbose); err != nil {
			fmt.Fprintf(os.Stderr, "Error generating blacklist: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Generated: %s\n", outputPath)
	}

	// Generate cn_whitelist.k2r.gz
	whitelistPath := filepath.Join(clashRulesDir, "cn_whitelist.yml")
	if _, err := os.Stat(whitelistPath); err == nil {
		outputPath := filepath.Join(*outputDir, "cn_whitelist.k2r.gz")
		slog.Info("generating whitelist", "input", whitelistPath, "output", outputPath)
		if err := convertClashYAML(whitelistPath, outputPath, *verbose); err != nil {
			fmt.Fprintf(os.Stderr, "Error generating whitelist: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Generated: %s\n", outputPath)
	}

	fmt.Printf("All rule files generated in %s\n", *outputDir)
}

// runGeneratePorn implements the generate-porn subcommand.
func runGeneratePorn(args []string) {
	fs := flag.NewFlagSet("generate-porn", flag.ExitOnError)
	outputFile := fs.String("o", "output/porn_domains.k2r.gz", "Output file path (.k2r.gz)")
	verbose := fs.Bool("v", false, "Verbose output")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if *verbose {
		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug})))
	}

	// Create output directory if needed
	if dir := filepath.Dir(*outputFile); dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			fmt.Fprintf(os.Stderr, "Error creating output directory: %v\n", err)
			os.Exit(1)
		}
	}

	if err := generatePornDomains(*outputFile, *verbose); err != nil {
		fmt.Fprintf(os.Stderr, "Error generating porn domain list: %v\n", err)
		os.Exit(1)
	}
}

// ─── Clash YAML conversion ────────────────────────────────────────────────────

// clashConfig represents the top-level Clash configuration structure.
type clashConfig struct {
	Rules         []string                   `yaml:"rules"`
	RuleProviders map[string]*ruleProvider   `yaml:"rule-providers"`
}

// ruleProvider represents a Clash rule provider definition.
type ruleProvider struct {
	Type     string `yaml:"type"`
	Behavior string `yaml:"behavior"`
	URL      string `yaml:"url"`
	Path     string `yaml:"path"`
	Interval int    `yaml:"interval"`
}

// providerPayload represents a loaded rule provider payload.
type providerPayload struct {
	Payload []string `yaml:"payload"`
}

// sliceDataType categorizes slices by their rule type.
type sliceDataType int

const (
	sliceTypeDomains sliceDataType = iota
	sliceTypeCIDRv4
	sliceTypeCIDRv6
	sliceTypeGeoIP
)

// sliceAccumulator collects rules for a single slice.
type sliceAccumulator struct {
	kind    sliceDataType
	target  uint8
	domains []string
	cidrsV4 []cidrV4Entry
	cidrsV6 []cidrV6Entry
	geoips  []string
}

// cidrV4Entry stores an IPv4 CIDR network address and prefix length.
type cidrV4Entry struct {
	network   uint32
	prefixLen uint8
}

// cidrV6Entry stores an IPv6 CIDR network address and prefix length.
type cidrV6Entry struct {
	network   [16]byte
	prefixLen uint8
}

// parseTarget converts a Clash target string to a uint8 value.
func parseTarget(s string) uint8 {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "DIRECT":
		return 0
	case "PROXY":
		return 1
	case "REJECT":
		return 2
	default:
		return 0
	}
}

// httpClient is a shared HTTP client with a timeout suitable for large file downloads.
var httpClient = &http.Client{Timeout: 5 * time.Minute}

// downloadText fetches the content at url as a string.
func downloadText(url string) (string, error) {
	resp, err := httpClient.Get(url)
	if err != nil {
		return "", fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GET %s: HTTP %d", url, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("reading response from %s: %w", url, err)
	}
	return string(body), nil
}

// parseProviderContent parses a rule provider payload (YAML or plain text).
func parseProviderContent(content string) []string {
	trimmed := strings.TrimSpace(content)

	// Try YAML payload format: payload:\n  - rule1\n  - rule2
	if strings.HasPrefix(trimmed, "payload:") {
		var pp providerPayload
		if err := yaml.Unmarshal([]byte(trimmed), &pp); err == nil && len(pp.Payload) > 0 {
			return pp.Payload
		}
	}

	// Plain text format: one rule per line
	var result []string
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		result = append(result, line)
	}
	return result
}

// loadProvider downloads or reads inline provider rules.
func loadProvider(name string, provider *ruleProvider, verbose bool) ([]string, error) {
	if provider.URL == "" {
		return nil, nil
	}

	if verbose {
		slog.Debug("downloading provider", "name", name, "url", provider.URL)
	}

	content, err := downloadText(provider.URL)
	if err != nil {
		return nil, fmt.Errorf("downloading provider %q: %w", name, err)
	}

	rules := parseProviderContent(content)
	if verbose {
		slog.Debug("loaded provider", "name", name, "rules", len(rules))
	}
	return rules, nil
}

// convertClashYAML converts a Clash YAML config file to K2RULEV2 binary format.
func convertClashYAML(inputPath, outputPath string, verbose bool) error {
	data, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("reading %s: %w", inputPath, err)
	}

	var config clashConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("parsing YAML %s: %w", inputPath, err)
	}

	// Load all rule providers
	providerRules := make(map[string][]string)
	for name, provider := range config.RuleProviders {
		rules, err := loadProvider(name, provider, verbose)
		if err != nil {
			slog.Warn("failed to load provider, skipping", "name", name, "error", err)
			continue
		}
		providerRules[name] = rules
	}

	// Process rules into slices
	var accumulators []*sliceAccumulator
	var fallbackTarget uint8 = 0 // default: DIRECT

	for _, ruleStr := range config.Rules {
		parts := strings.SplitN(ruleStr, ",", 3)
		if len(parts) < 2 {
			continue
		}

		ruleType := strings.TrimSpace(parts[0])

		if ruleType == "MATCH" {
			if len(parts) >= 2 {
				fallbackTarget = parseTarget(parts[len(parts)-1])
			}
			continue
		}

		if len(parts) < 3 {
			continue
		}

		target := parseTarget(parts[len(parts)-1])

		switch ruleType {
		case "RULE-SET":
			providerName := strings.TrimSpace(parts[1])
			provider := config.RuleProviders[providerName]
			behavior := "domain"
			if provider != nil {
				behavior = provider.Behavior
			}
			rules := providerRules[providerName]
			addProviderSlices(&accumulators, behavior, rules, target, verbose)

		case "GEOIP":
			country := strings.TrimSpace(parts[1])
			if country == "LAN" {
				addLANSlices(&accumulators, target)
			} else {
				mergeOrAppendGeoIP(&accumulators, country, target)
			}

		case "DOMAIN", "DOMAIN-SUFFIX":
			domain := strings.TrimSpace(parts[1])
			mergeOrAppendDomain(&accumulators, domain, target)

		case "IP-CIDR":
			cidr := strings.TrimSpace(parts[1])
			if entry, ok := parseCIDRv4(cidr); ok {
				mergeOrAppendCIDRv4(&accumulators, entry, target)
			}

		case "IP-CIDR6":
			cidr := strings.TrimSpace(parts[1])
			if entry, ok := parseCIDRv6(cidr); ok {
				mergeOrAppendCIDRv6(&accumulators, entry, target)
			}
		}
	}

	// Serialize to K2RULEV2 binary
	binaryData, err := buildK2RuleV2(accumulators, fallbackTarget)
	if err != nil {
		return fmt.Errorf("building binary: %w", err)
	}

	// Write output (gzip-compressed if .gz extension)
	if err := writeOutput(outputPath, binaryData); err != nil {
		return fmt.Errorf("writing %s: %w", outputPath, err)
	}

	if verbose {
		slog.Info("converted", "input", inputPath, "output", outputPath, "bytes", len(binaryData))
	}
	return nil
}

// addProviderSlices adds slices from a rule provider.
func addProviderSlices(accs *[]*sliceAccumulator, behavior string, rules []string, target uint8, verbose bool) {
	if len(rules) == 0 {
		return
	}

	switch behavior {
	case "domain":
		var domains []string
		for _, rule := range rules {
			rule = strings.TrimSpace(rule)
			if rule == "" || strings.HasPrefix(rule, "#") {
				continue
			}
			// Convert Clash suffix formats to plain domain
			if strings.HasPrefix(rule, "+.") {
				rule = rule[2:]
			} else if strings.HasPrefix(rule, ".") {
				rule = rule[1:]
			}
			domains = append(domains, rule)
		}
		if len(domains) > 0 {
			mergeOrAppendDomains(accs, domains, target)
		}

	case "ipcidr":
		var v4s []cidrV4Entry
		var v6s []cidrV6Entry
		for _, rule := range rules {
			rule = strings.TrimSpace(rule)
			if rule == "" || strings.HasPrefix(rule, "#") {
				continue
			}
			if entry, ok := parseCIDRv4(rule); ok {
				v4s = append(v4s, entry)
			} else if entry, ok := parseCIDRv6(rule); ok {
				v6s = append(v6s, entry)
			}
		}
		if len(v4s) > 0 {
			mergeOrAppendCIDRv4s(accs, v4s, target)
		}
		if len(v6s) > 0 {
			mergeOrAppendCIDRv6s(accs, v6s, target)
		}

	case "classical":
		for _, rule := range rules {
			parseClassicalRule(accs, rule, target)
		}
	}
}

// parseClassicalRule parses a classical Clash rule string.
func parseClassicalRule(accs *[]*sliceAccumulator, rule string, target uint8) {
	parts := strings.SplitN(rule, ",", 3)
	if len(parts) < 2 {
		return
	}
	ruleType := strings.TrimSpace(parts[0])
	value := strings.TrimSpace(parts[1])

	switch ruleType {
	case "DOMAIN", "DOMAIN-SUFFIX":
		mergeOrAppendDomain(accs, value, target)
	case "IP-CIDR":
		if entry, ok := parseCIDRv4(value); ok {
			mergeOrAppendCIDRv4(accs, entry, target)
		}
	case "IP-CIDR6":
		if entry, ok := parseCIDRv6(value); ok {
			mergeOrAppendCIDRv6(accs, entry, target)
		}
	case "GEOIP":
		if value == "LAN" {
			addLANSlices(accs, target)
		} else {
			mergeOrAppendGeoIP(accs, value, target)
		}
	}
}

// addLANSlices adds the standard private IPv4 and IPv6 CIDR slices.
func addLANSlices(accs *[]*sliceAccumulator, target uint8) {
	v4s := []cidrV4Entry{
		{network: 0x7F000000, prefixLen: 8},  // 127.0.0.0/8
		{network: 0x0A000000, prefixLen: 8},  // 10.0.0.0/8
		{network: 0xAC100000, prefixLen: 12}, // 172.16.0.0/12
		{network: 0xC0A80000, prefixLen: 16}, // 192.168.0.0/16
		{network: 0xA9FE0000, prefixLen: 16}, // 169.254.0.0/16
	}
	mergeOrAppendCIDRv4s(accs, v4s, target)

	fc00 := [16]byte{0xFC, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	fe80 := [16]byte{0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	lo6 := [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	v6s := []cidrV6Entry{
		{network: fc00, prefixLen: 7},
		{network: fe80, prefixLen: 10},
		{network: lo6, prefixLen: 128},
	}
	mergeOrAppendCIDRv6s(accs, v6s, target)
}

// ─── Merge helpers ────────────────────────────────────────────────────────────

func lastAcc(accs *[]*sliceAccumulator) *sliceAccumulator {
	if len(*accs) == 0 {
		return nil
	}
	return (*accs)[len(*accs)-1]
}

func mergeOrAppendDomain(accs *[]*sliceAccumulator, domain string, target uint8) {
	if last := lastAcc(accs); last != nil && last.kind == sliceTypeDomains && last.target == target {
		last.domains = append(last.domains, domain)
		return
	}
	*accs = append(*accs, &sliceAccumulator{kind: sliceTypeDomains, target: target, domains: []string{domain}})
}

func mergeOrAppendDomains(accs *[]*sliceAccumulator, domains []string, target uint8) {
	if last := lastAcc(accs); last != nil && last.kind == sliceTypeDomains && last.target == target {
		last.domains = append(last.domains, domains...)
		return
	}
	*accs = append(*accs, &sliceAccumulator{kind: sliceTypeDomains, target: target, domains: domains})
}

func mergeOrAppendCIDRv4(accs *[]*sliceAccumulator, entry cidrV4Entry, target uint8) {
	if last := lastAcc(accs); last != nil && last.kind == sliceTypeCIDRv4 && last.target == target {
		last.cidrsV4 = append(last.cidrsV4, entry)
		return
	}
	*accs = append(*accs, &sliceAccumulator{kind: sliceTypeCIDRv4, target: target, cidrsV4: []cidrV4Entry{entry}})
}

func mergeOrAppendCIDRv4s(accs *[]*sliceAccumulator, entries []cidrV4Entry, target uint8) {
	if last := lastAcc(accs); last != nil && last.kind == sliceTypeCIDRv4 && last.target == target {
		last.cidrsV4 = append(last.cidrsV4, entries...)
		return
	}
	*accs = append(*accs, &sliceAccumulator{kind: sliceTypeCIDRv4, target: target, cidrsV4: entries})
}

func mergeOrAppendCIDRv6(accs *[]*sliceAccumulator, entry cidrV6Entry, target uint8) {
	if last := lastAcc(accs); last != nil && last.kind == sliceTypeCIDRv6 && last.target == target {
		last.cidrsV6 = append(last.cidrsV6, entry)
		return
	}
	*accs = append(*accs, &sliceAccumulator{kind: sliceTypeCIDRv6, target: target, cidrsV6: []cidrV6Entry{entry}})
}

func mergeOrAppendCIDRv6s(accs *[]*sliceAccumulator, entries []cidrV6Entry, target uint8) {
	if last := lastAcc(accs); last != nil && last.kind == sliceTypeCIDRv6 && last.target == target {
		last.cidrsV6 = append(last.cidrsV6, entries...)
		return
	}
	*accs = append(*accs, &sliceAccumulator{kind: sliceTypeCIDRv6, target: target, cidrsV6: entries})
}

func mergeOrAppendGeoIP(accs *[]*sliceAccumulator, country string, target uint8) {
	if last := lastAcc(accs); last != nil && last.kind == sliceTypeGeoIP && last.target == target {
		last.geoips = append(last.geoips, country)
		return
	}
	*accs = append(*accs, &sliceAccumulator{kind: sliceTypeGeoIP, target: target, geoips: []string{country}})
}

// ─── CIDR parsing ─────────────────────────────────────────────────────────────

func parseCIDRv4(cidr string) (cidrV4Entry, bool) {
	// Strip ,no-resolve suffix (Clash uses this)
	if idx := strings.Index(cidr, ","); idx != -1 {
		cidr = cidr[:idx]
	}
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return cidrV4Entry{}, false
	}
	if ipNet.IP.To4() == nil {
		return cidrV4Entry{}, false
	}
	ip4 := ipNet.IP.To4()
	network := uint32(ip4[0])<<24 | uint32(ip4[1])<<16 | uint32(ip4[2])<<8 | uint32(ip4[3])
	ones, _ := ipNet.Mask.Size()
	return cidrV4Entry{network: network, prefixLen: uint8(ones)}, true
}

func parseCIDRv6(cidr string) (cidrV6Entry, bool) {
	// Strip ,no-resolve suffix
	if idx := strings.Index(cidr, ","); idx != -1 {
		cidr = cidr[:idx]
	}
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return cidrV6Entry{}, false
	}
	if ipNet.IP.To4() != nil {
		return cidrV6Entry{}, false // skip IPv4-mapped
	}
	ip16 := ipNet.IP.To16()
	if ip16 == nil {
		return cidrV6Entry{}, false
	}
	var network [16]byte
	copy(network[:], ip16)
	ones, _ := ipNet.Mask.Size()
	return cidrV6Entry{network: network, prefixLen: uint8(ones)}, true
}

// ─── K2RULEV2 binary format builder ──────────────────────────────────────────
//
// Layout:
//   Header (64 bytes):
//     [0:8]   Magic "K2RULEV2"
//     [8:12]  Version (uint32 LE) = 1
//     [12:16] SliceCount (uint32 LE)
//     [16]    FallbackTarget (uint8)
//     [17:20] Reserved (3 bytes)
//     [20:28] Timestamp (int64 LE)
//     [28:44] Checksum (16 bytes, SHA-256 first 16)
//     [44:64] Reserved (20 bytes)
//   Slice index (SliceCount * 16 bytes):
//     [0]     SliceType (uint8)
//     [1]     Target (uint8)
//     [2:4]   Reserved (2 bytes)
//     [4:8]   Offset (uint32 LE) — from file start
//     [8:12]  Size (uint32 LE)
//     [12:16] Count (uint32 LE)
//   Slice data sections (variable)

const (
	k2rMagic      = "K2RULEV2"
	k2rVersion    = 1
	k2rHeaderSize = 64
	k2rEntrySize  = 16

	k2rSliceTypeFstDomain = 0x01
	k2rSliceTypeCIDRv4    = 0x02
	k2rSliceTypeCIDRv6    = 0x03
	k2rSliceTypeGeoIP     = 0x04
)

// sliceBuf holds the serialized data for a single slice plus its index entry.
type sliceBuf struct {
	sliceType uint8
	target    uint8
	count     uint32
	data      []byte
}

// buildK2RuleV2 serializes all slices into the K2RULEV2 binary format.
func buildK2RuleV2(accs []*sliceAccumulator, fallback uint8) ([]byte, error) {
	var slices []sliceBuf

	for _, acc := range accs {
		var sb sliceBuf
		var err error

		switch acc.kind {
		case sliceTypeDomains:
			sb, err = buildDomainSlice(acc.domains, acc.target)
		case sliceTypeCIDRv4:
			sb, err = buildCIDRv4Slice(acc.cidrsV4, acc.target)
		case sliceTypeCIDRv6:
			sb, err = buildCIDRv6Slice(acc.cidrsV6, acc.target)
		case sliceTypeGeoIP:
			sb, err = buildGeoIPSlice(acc.geoips, acc.target)
		}
		if err != nil {
			return nil, err
		}
		slices = append(slices, sb)
	}

	sliceCount := uint32(len(slices))
	indexSize := int(sliceCount) * k2rEntrySize
	dataStart := k2rHeaderSize + indexSize

	// Calculate offsets for each slice
	currentOffset := dataStart
	for i := range slices {
		slices[i].data = slices[i].data // already built
		_ = currentOffset
		currentOffset += len(slices[i].data)
	}

	// Total size
	totalSize := currentOffset
	buf := make([]byte, totalSize)

	// Write header
	copy(buf[0:8], k2rMagic)
	binary.LittleEndian.PutUint32(buf[8:12], k2rVersion)
	binary.LittleEndian.PutUint32(buf[12:16], sliceCount)
	buf[16] = fallback
	// buf[17:20] = reserved (zeros)
	timestamp := time.Now().Unix()
	binary.LittleEndian.PutUint64(buf[20:28], uint64(timestamp))
	// buf[28:44] = checksum (zeros for now)
	// buf[44:64] = reserved (zeros)

	// Write slice index
	offset := dataStart
	for i, s := range slices {
		entryStart := k2rHeaderSize + i*k2rEntrySize
		buf[entryStart] = s.sliceType
		buf[entryStart+1] = s.target
		// [2:4] reserved
		binary.LittleEndian.PutUint32(buf[entryStart+4:], uint32(offset))
		binary.LittleEndian.PutUint32(buf[entryStart+8:], uint32(len(s.data)))
		binary.LittleEndian.PutUint32(buf[entryStart+12:], s.count)
		offset += len(s.data)
	}

	// Write slice data
	pos := dataStart
	for _, s := range slices {
		copy(buf[pos:], s.data)
		pos += len(s.data)
	}

	return buf, nil
}

// buildDomainSlice builds an FST domain slice.
func buildDomainSlice(domains []string, target uint8) (sliceBuf, error) {
	// Normalize: add leading dot for suffix matching, reverse for FST
	reversedDomains := make([]string, 0, len(domains))
	for _, d := range domains {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" {
			continue
		}
		if !strings.HasPrefix(d, ".") {
			d = "." + d
		}
		// Reverse for FST (common suffix prefix compression)
		reversed := reverseString(d)
		reversedDomains = append(reversedDomains, reversed)
	}

	// Deduplicate and sort for FST construction
	sortedReversed := appendSortedStrings(reversedDomains)

	fstData := buildFST(sortedReversed)

	return sliceBuf{
		sliceType: k2rSliceTypeFstDomain,
		target:    target,
		count:     uint32(len(sortedReversed)),
		data:      fstData,
	}, nil
}

// buildCIDRv4Slice builds an IPv4 CIDR slice.
// Each entry is 8 bytes: network (4 bytes BE) + prefix_len (1 byte) + padding (3 bytes).
func buildCIDRv4Slice(cidrs []cidrV4Entry, target uint8) (sliceBuf, error) {
	sorted := make([]cidrV4Entry, len(cidrs))
	copy(sorted, cidrs)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].network < sorted[j].network })

	data := make([]byte, len(sorted)*8)
	for i, e := range sorted {
		binary.BigEndian.PutUint32(data[i*8:], e.network)
		data[i*8+4] = e.prefixLen
		// data[i*8+5:i*8+8] = 0 (padding)
	}

	return sliceBuf{
		sliceType: k2rSliceTypeCIDRv4,
		target:    target,
		count:     uint32(len(sorted)),
		data:      data,
	}, nil
}

// buildCIDRv6Slice builds an IPv6 CIDR slice.
// Each entry is 24 bytes: network (16 bytes) + prefix_len (1 byte) + padding (7 bytes).
func buildCIDRv6Slice(cidrs []cidrV6Entry, target uint8) (sliceBuf, error) {
	sorted := make([]cidrV6Entry, len(cidrs))
	copy(sorted, cidrs)
	sort.Slice(sorted, func(i, j int) bool {
		for k := 0; k < 16; k++ {
			if sorted[i].network[k] != sorted[j].network[k] {
				return sorted[i].network[k] < sorted[j].network[k]
			}
		}
		return false
	})

	data := make([]byte, len(sorted)*24)
	for i, e := range sorted {
		copy(data[i*24:], e.network[:])
		data[i*24+16] = e.prefixLen
		// data[i*24+17:i*24+24] = 0 (padding)
	}

	return sliceBuf{
		sliceType: k2rSliceTypeCIDRv6,
		target:    target,
		count:     uint32(len(sorted)),
		data:      data,
	}, nil
}

// buildGeoIPSlice builds a GeoIP country code slice.
// Each entry is 4 bytes: country_code (2 bytes) + padding (2 bytes).
func buildGeoIPSlice(countries []string, target uint8) (sliceBuf, error) {
	data := make([]byte, len(countries)*4)
	for i, c := range countries {
		c = strings.ToUpper(strings.TrimSpace(c))
		if len(c) >= 1 {
			data[i*4] = c[0]
		}
		if len(c) >= 2 {
			data[i*4+1] = c[1]
		}
		// data[i*4+2:i*4+4] = 0 (padding)
	}

	return sliceBuf{
		sliceType: k2rSliceTypeGeoIP,
		target:    target,
		count:     uint32(len(countries)),
		data:      data,
	}, nil
}

// reverseString reverses a UTF-8 string byte-by-byte (domain names are ASCII).
func reverseString(s string) string {
	b := []byte(s)
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return string(b)
}

// ─── Output writing ───────────────────────────────────────────────────────────

// writeOutput writes data to path, gzip-compressing if the path ends in .gz.
func writeOutput(path string, data []byte) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	if strings.HasSuffix(path, ".gz") {
		w, err := gzip.NewWriterLevel(f, gzip.BestCompression)
		if err != nil {
			return err
		}
		defer w.Close()
		_, err = w.Write(data)
		return err
	}

	_, err = f.Write(data)
	return err
}

// ─── Porn domain generation ───────────────────────────────────────────────────

const (
	pornDomainsMetaURL = "https://cdn.jsdelivr.net/gh/Bon-Appetit/porn-domains@main/meta.json"
	pornDomainsBaseURL = "https://cdn.jsdelivr.net/gh/Bon-Appetit/porn-domains@main/"
)

// pornMeta is a minimal JSON structure from the porn-domains meta.json.
type pornMeta struct {
	Blocklist struct {
		Name    string `yaml:"name"`
		Updated string `yaml:"updated"`
		Lines   int64  `yaml:"lines"`
	} `yaml:"blocklist"`
}

// generatePornDomains downloads the porn domain list and generates a k2r file.
func generatePornDomains(outputPath string, verbose bool) error {
	if verbose {
		slog.Info("fetching porn domain meta")
	}

	// Download meta.json (JSON format, but we parse with a simple approach)
	metaContent, err := downloadText(pornDomainsMetaURL)
	if err != nil {
		return fmt.Errorf("fetching meta.json: %w", err)
	}

	// Parse JSON meta using simple extraction (avoid json import for minimal deps)
	blocklistName, updatedDate := parsePornMeta(metaContent)
	if blocklistName == "" {
		return fmt.Errorf("could not parse blocklist name from meta.json")
	}

	if verbose {
		slog.Info("downloading porn blocklist", "file", blocklistName, "updated", updatedDate)
	}

	blocklistURL := pornDomainsBaseURL + blocklistName
	blocklistContent, err := downloadText(blocklistURL)
	if err != nil {
		return fmt.Errorf("fetching blocklist: %w", err)
	}

	// Parse domains
	var allDomains []string
	for _, line := range strings.Split(blocklistContent, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		allDomains = append(allDomains, line)
	}

	if verbose {
		slog.Info("parsed porn domains", "count", len(allDomains))
	}

	// Build domain slice: use suffix match (leading dot)
	accs := []*sliceAccumulator{
		{kind: sliceTypeDomains, target: 2 /* REJECT */, domains: allDomains},
	}

	binaryData, err := buildK2RuleV2(accs, 0 /* DIRECT fallback */)
	if err != nil {
		return fmt.Errorf("building binary: %w", err)
	}

	if err := writeOutput(outputPath, binaryData); err != nil {
		return fmt.Errorf("writing %s: %w", outputPath, err)
	}

	fmt.Printf("Generated porn domain list: %s\n", outputPath)
	fmt.Printf("  Updated: %s\n", updatedDate)
	fmt.Printf("  Total domains: %d\n", len(allDomains))

	return nil
}

// parsePornMeta extracts the blocklist filename and updated date from meta.json content.
// Uses simple string scanning to avoid importing encoding/json.
func parsePornMeta(content string) (name, updated string) {
	// Look for "blocklist" section and extract "name" and "updated" fields
	// The JSON looks like: {"blocklist":{"name":"...","updated":"...","lines":...}, ...}
	content = strings.ReplaceAll(content, " ", "")
	content = strings.ReplaceAll(content, "\n", "")
	content = strings.ReplaceAll(content, "\t", "")

	blocklistIdx := strings.Index(content, `"blocklist":{`)
	if blocklistIdx == -1 {
		return "", ""
	}
	section := content[blocklistIdx:]

	name = extractJSONString(section, "name")
	updated = extractJSONString(section, "updated")
	return name, updated
}

// extractJSONString extracts a simple string value from a JSON snippet.
func extractJSONString(content, key string) string {
	needle := `"` + key + `":"`
	idx := strings.Index(content, needle)
	if idx == -1 {
		return ""
	}
	rest := content[idx+len(needle):]
	end := strings.Index(rest, `"`)
	if end == -1 {
		return ""
	}
	return rest[:end]
}
