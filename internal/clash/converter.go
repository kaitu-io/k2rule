package clash

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"

	"github.com/kaitu-io/k2rule/internal/slice"
	"gopkg.in/yaml.v3"
)

// clashConfig represents the structure of a Clash YAML configuration file.
type clashConfig struct {
	Rules         []string                `yaml:"rules"`
	RuleProviders map[string]ruleProvider `yaml:"rule-providers"`
}

// ruleProvider represents a rule-set provider definition in a Clash config.
type ruleProvider struct {
	Type     string   `yaml:"type"`
	Behavior string   `yaml:"behavior"`
	URL      string   `yaml:"url"`
	Rules    []string `yaml:"rules"`
}

// providerPayload represents the YAML payload format from downloaded rule providers.
type providerPayload struct {
	Payload []string `yaml:"payload"`
}

// sliceAccumulator is an intermediate representation of a slice being built.
type sliceAccumulator struct {
	sliceType string   // "domain", "ipcidr_v4", "ipcidr_v6", "geoip"
	target    uint8    // routing target
	domains   []string
	cidrsV4   []slice.CidrV4Entry
	cidrsV6   []slice.CidrV6Entry
	geoips    []string
}

// SliceConverter converts Clash YAML configurations to K2RULEV2 binary format.
//
// The converter preserves rule ordering (first match wins) and uses the
// SliceTypeSortedDomain format for domain sets with binary search matching.
// Provider rules must be pre-loaded via SetProviderRules or LoadProvider
// before calling Convert.
type SliceConverter struct {
	providerRules map[string][]string
}

// NewSliceConverter creates a new SliceConverter.
func NewSliceConverter() *SliceConverter {
	return &SliceConverter{
		providerRules: make(map[string][]string),
	}
}

// SetProviderRules sets pre-loaded rules for a named provider.
//
// Rules should be in the raw format returned by the provider endpoint
// (either plain text or YAML payload format). These rules bypass HTTP
// downloading and are used directly during Convert.
func (c *SliceConverter) SetProviderRules(name string, rules []string) {
	c.providerRules[name] = rules
}

// LoadProvider parses provider rules from YAML payload content and stores them.
//
// The content should be in Clash provider YAML format:
//
//	payload:
//	  - rule1
//	  - rule2
func (c *SliceConverter) LoadProvider(name, content string) error {
	// Try YAML payload format first
	trimmed := strings.TrimSpace(content)
	if strings.HasPrefix(trimmed, "payload:") {
		var payload providerPayload
		if err := yaml.Unmarshal([]byte(content), &payload); err != nil {
			return fmt.Errorf("parse provider YAML: %w", err)
		}
		c.providerRules[name] = payload.Payload
		return nil
	}

	// Plain text format: one rule per line
	rules := make([]string, 0)
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		rules = append(rules, line)
	}
	c.providerRules[name] = rules
	return nil
}

// Convert parses a Clash YAML configuration and converts it to K2RULEV2 binary format.
//
// The fallback target (from MATCH rule) is embedded in the header. Rules are
// processed in order and adjacent same-type same-target slices are merged.
// Provider rules must be pre-loaded; missing providers produce empty slices.
func (c *SliceConverter) Convert(yamlContent string) ([]byte, error) {
	var config clashConfig
	if err := yaml.Unmarshal([]byte(yamlContent), &config); err != nil {
		return nil, fmt.Errorf("parse clash config: %w", err)
	}

	var accumulators []sliceAccumulator
	var fallback uint8 = 0 // default Direct

	for _, ruleStr := range config.Rules {
		parts := strings.SplitN(ruleStr, ",", -1)
		if len(parts) < 2 {
			continue
		}

		ruleType := strings.TrimSpace(parts[0])
		lastPart := strings.TrimSpace(parts[len(parts)-1])
		target := parseTarget(lastPart)

		switch ruleType {
		case "RULE-SET":
			if len(parts) < 3 {
				continue
			}
			providerName := strings.TrimSpace(parts[1])
			behavior := "domain"
			if p, ok := config.RuleProviders[providerName]; ok {
				behavior = p.Behavior
			}

			rules := c.getProviderRules(providerName, config.RuleProviders)
			c.addProviderSlices(&accumulators, behavior, rules, target)

		case "GEOIP":
			if len(parts) >= 3 {
				country := strings.TrimSpace(parts[1])
				if country == "LAN" {
					addLANSlices(&accumulators, target)
				} else {
					addOrMerge(&accumulators, sliceAccumulator{
						sliceType: "geoip",
						target:    target,
						geoips:    []string{country},
					})
				}
			}

		case "DOMAIN":
			if len(parts) >= 3 {
				domain := strings.TrimSpace(parts[1])
				addOrMerge(&accumulators, sliceAccumulator{
					sliceType: "domain",
					target:    target,
					domains:   []string{domain},
				})
			}

		case "DOMAIN-SUFFIX":
			if len(parts) >= 3 {
				suffix := strings.TrimSpace(parts[1])
				addOrMerge(&accumulators, sliceAccumulator{
					sliceType: "domain",
					target:    target,
					domains:   []string{suffix},
				})
			}

		case "IP-CIDR":
			if len(parts) >= 3 {
				cidr := strings.TrimSpace(parts[1])
				if entry, ok := parseCIDRv4(cidr); ok {
					addOrMerge(&accumulators, sliceAccumulator{
						sliceType: "ipcidr_v4",
						target:    target,
						cidrsV4:   []slice.CidrV4Entry{entry},
					})
				}
			}

		case "IP-CIDR6":
			if len(parts) >= 3 {
				cidr := strings.TrimSpace(parts[1])
				if entry, ok := parseCIDRv6(cidr); ok {
					addOrMerge(&accumulators, sliceAccumulator{
						sliceType: "ipcidr_v6",
						target:    target,
						cidrsV6:   []slice.CidrV6Entry{entry},
					})
				}
			}

		case "MATCH":
			fallback = target
		}
	}

	// Build binary output
	w := slice.NewSliceWriter(fallback)

	for _, acc := range accumulators {
		switch acc.sliceType {
		case "domain":
			if err := w.AddDomainSlice(acc.domains, acc.target); err != nil {
				return nil, fmt.Errorf("add domain slice: %w", err)
			}
		case "ipcidr_v4":
			if err := w.AddCidrV4Slice(acc.cidrsV4, acc.target); err != nil {
				return nil, fmt.Errorf("add cidr v4 slice: %w", err)
			}
		case "ipcidr_v6":
			if err := w.AddCidrV6Slice(acc.cidrsV6, acc.target); err != nil {
				return nil, fmt.Errorf("add cidr v6 slice: %w", err)
			}
		case "geoip":
			if err := w.AddGeoIPSlice(acc.geoips, acc.target); err != nil {
				return nil, fmt.Errorf("add geoip slice: %w", err)
			}
		}
	}

	return w.Build()
}

// getProviderRules returns the loaded provider rules or inline rules from the config.
func (c *SliceConverter) getProviderRules(name string, providers map[string]ruleProvider) []string {
	if rules, ok := c.providerRules[name]; ok {
		return rules
	}
	if p, ok := providers[name]; ok && len(p.Rules) > 0 {
		return p.Rules
	}
	return nil
}

// addProviderSlices processes provider rules based on behavior type and adds slices.
func (c *SliceConverter) addProviderSlices(accumulators *[]sliceAccumulator, behavior string, rules []string, target uint8) {
	switch behavior {
	case "domain":
		var domains []string
		for _, rule := range rules {
			rule = strings.TrimSpace(rule)
			if rule == "" || strings.HasPrefix(rule, "#") {
				continue
			}
			// Handle Clash "+." prefix for wildcard domain matching
			if strings.HasPrefix(rule, "+.") {
				rule = rule[2:]
			} else if strings.HasPrefix(rule, ".") {
				rule = rule[1:]
			}
			domains = append(domains, rule)
		}
		if len(domains) > 0 {
			addOrMerge(accumulators, sliceAccumulator{
				sliceType: "domain",
				target:    target,
				domains:   domains,
			})
		}

	case "ipcidr":
		var v4cidrs []slice.CidrV4Entry
		var v6cidrs []slice.CidrV6Entry
		for _, rule := range rules {
			rule = strings.TrimSpace(rule)
			if rule == "" || strings.HasPrefix(rule, "#") {
				continue
			}
			if entry, ok := parseCIDRv4(rule); ok {
				v4cidrs = append(v4cidrs, entry)
			} else if entry, ok := parseCIDRv6(rule); ok {
				v6cidrs = append(v6cidrs, entry)
			}
		}
		if len(v4cidrs) > 0 {
			addOrMerge(accumulators, sliceAccumulator{
				sliceType: "ipcidr_v4",
				target:    target,
				cidrsV4:   v4cidrs,
			})
		}
		if len(v6cidrs) > 0 {
			addOrMerge(accumulators, sliceAccumulator{
				sliceType: "ipcidr_v6",
				target:    target,
				cidrsV6:   v6cidrs,
			})
		}

	case "classical":
		for _, rule := range rules {
			rule = strings.TrimSpace(rule)
			if rule == "" || strings.HasPrefix(rule, "#") {
				continue
			}
			parts := strings.SplitN(rule, ",", -1)
			if len(parts) < 2 {
				continue
			}
			ruleType := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			switch ruleType {
			case "DOMAIN", "DOMAIN-SUFFIX":
				addOrMerge(accumulators, sliceAccumulator{
					sliceType: "domain",
					target:    target,
					domains:   []string{value},
				})
			case "IP-CIDR":
				if entry, ok := parseCIDRv4(value); ok {
					addOrMerge(accumulators, sliceAccumulator{
						sliceType: "ipcidr_v4",
						target:    target,
						cidrsV4:   []slice.CidrV4Entry{entry},
					})
				}
			case "IP-CIDR6":
				if entry, ok := parseCIDRv6(value); ok {
					addOrMerge(accumulators, sliceAccumulator{
						sliceType: "ipcidr_v6",
						target:    target,
						cidrsV6:   []slice.CidrV6Entry{entry},
					})
				}
			case "GEOIP":
				if value == "LAN" {
					addLANSlices(accumulators, target)
				} else {
					addOrMerge(accumulators, sliceAccumulator{
						sliceType: "geoip",
						target:    target,
						geoips:    []string{value},
					})
				}
			}
		}
	}
}

// addOrMerge adds a new accumulator or merges with the last one if compatible.
// Two accumulators are compatible if they have the same sliceType and target.
func addOrMerge(accumulators *[]sliceAccumulator, acc sliceAccumulator) {
	if len(*accumulators) > 0 {
		last := &(*accumulators)[len(*accumulators)-1]
		if last.sliceType == acc.sliceType && last.target == acc.target {
			last.domains = append(last.domains, acc.domains...)
			last.cidrsV4 = append(last.cidrsV4, acc.cidrsV4...)
			last.cidrsV6 = append(last.cidrsV6, acc.cidrsV6...)
			last.geoips = append(last.geoips, acc.geoips...)
			return
		}
	}
	*accumulators = append(*accumulators, acc)
}

// addLANSlices adds private IPv4 and IPv6 CIDR ranges as separate slices.
func addLANSlices(accumulators *[]sliceAccumulator, target uint8) {
	// IPv4 private ranges
	v4cidrs := []slice.CidrV4Entry{
		{Network: 0x7F000000, PrefixLen: 8},  // 127.0.0.0/8
		{Network: 0x0A000000, PrefixLen: 8},  // 10.0.0.0/8
		{Network: 0xAC100000, PrefixLen: 12}, // 172.16.0.0/12
		{Network: 0xC0A80000, PrefixLen: 16}, // 192.168.0.0/16
		{Network: 0xA9FE0000, PrefixLen: 16}, // 169.254.0.0/16
	}
	addOrMerge(accumulators, sliceAccumulator{
		sliceType: "ipcidr_v4",
		target:    target,
		cidrsV4:   v4cidrs,
	})

	// IPv6 private ranges
	v6cidrs := []slice.CidrV6Entry{
		{Network: [16]byte{0xFC}, PrefixLen: 7},                                           // fc00::/7
		{Network: [16]byte{0xFE, 0x80}, PrefixLen: 10},                                    // fe80::/10
		{Network: [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, PrefixLen: 128}, // ::1/128
	}
	addOrMerge(accumulators, sliceAccumulator{
		sliceType: "ipcidr_v6",
		target:    target,
		cidrsV6:   v6cidrs,
	})
}

// parseTarget converts a Clash target string to a uint8 target value.
// Defaults to 0 (Direct) for unrecognized values.
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

// parseCIDRv4 parses an IPv4 CIDR string like "10.0.0.0/8".
// Returns the entry and true on success, zero value and false on failure.
func parseCIDRv4(cidr string) (slice.CidrV4Entry, bool) {
	// Remove trailing comma or other noise
	cidr = strings.TrimRight(cidr, ",")
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return slice.CidrV4Entry{}, false
	}

	ip4 := ipNet.IP.To4()
	if ip4 == nil {
		return slice.CidrV4Entry{}, false
	}

	prefixLen, _ := ipNet.Mask.Size()
	network := binary.BigEndian.Uint32(ip4)
	return slice.CidrV4Entry{
		Network:   network,
		PrefixLen: uint8(prefixLen),
	}, true
}

// parseCIDRv6 parses an IPv6 CIDR string like "fc00::/7".
// Returns the entry and true on success, zero value and false on failure.
func parseCIDRv6(cidr string) (slice.CidrV6Entry, bool) {
	cidr = strings.TrimRight(cidr, ",")
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return slice.CidrV6Entry{}, false
	}

	ip6 := ipNet.IP.To16()
	if ip6 == nil {
		return slice.CidrV6Entry{}, false
	}

	// Skip if it's actually an IPv4 address
	if ipNet.IP.To4() != nil {
		return slice.CidrV6Entry{}, false
	}

	prefixLen, _ := ipNet.Mask.Size()
	var network [16]byte
	copy(network[:], ip6)
	return slice.CidrV6Entry{
		Network:   network,
		PrefixLen: uint8(prefixLen),
	}, true
}
