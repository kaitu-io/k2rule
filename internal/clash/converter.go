// Package clash provides conversion from Clash YAML configurations to K2RULEV2 binary format.
package clash

import (
	"encoding/binary"
	"net"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/kaitu-io/k2rule/internal/slice"
)

// target constants matching Rust and Go codebase values.
const (
	targetDirect uint8 = 0
	targetProxy  uint8 = 1
	targetReject uint8 = 2
)

// parseTarget parses a Clash target string to its uint8 value.
// Unknown values default to Proxy.
func parseTarget(s string) uint8 {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "DIRECT":
		return targetDirect
	case "REJECT":
		return targetReject
	default:
		return targetProxy
	}
}

// sliceKind identifies the type of a collected slice.
type sliceKind int

const (
	kindDomain sliceKind = iota
	kindCidrV4
	kindCidrV6
	kindGeoIP
)

// sliceData holds the intermediate representation of a slice before writing.
type sliceData struct {
	kind    sliceKind
	target  uint8
	domains []string
	cidrV4  [][2]uint32 // [network_u32, prefix_len]
	cidrV6N [][16]byte
	cidrV6P []uint8
	geoips  []string
}

func (sd *sliceData) canMerge(other *sliceData) bool {
	return sd.kind == other.kind && sd.target == other.target
}

func (sd *sliceData) merge(other *sliceData) {
	switch sd.kind {
	case kindDomain:
		sd.domains = append(sd.domains, other.domains...)
	case kindCidrV4:
		sd.cidrV4 = append(sd.cidrV4, other.cidrV4...)
	case kindCidrV6:
		sd.cidrV6N = append(sd.cidrV6N, other.cidrV6N...)
		sd.cidrV6P = append(sd.cidrV6P, other.cidrV6P...)
	case kindGeoIP:
		sd.geoips = append(sd.geoips, other.geoips...)
	}
}

// clashConfig represents the top-level Clash configuration YAML structure.
type clashConfig struct {
	Rules         []string                `yaml:"rules"`
	RuleProviders map[string]ruleProvider `yaml:"rule-providers"`
}

// ruleProvider represents a Clash rule provider configuration.
type ruleProvider struct {
	Behavior string   `yaml:"behavior"`
	Rules    []string `yaml:"rules"`
	URL      string   `yaml:"url"`
}

// SliceConverter converts Clash YAML configurations to K2RULEV2 binary format.
type SliceConverter struct {
	// providerRules holds preloaded or externally set provider rules.
	// Keys are provider names; values are lists of rule strings.
	providerRules map[string][]string
}

// NewSliceConverter creates a new SliceConverter.
func NewSliceConverter() *SliceConverter {
	return &SliceConverter{
		providerRules: make(map[string][]string),
	}
}

// SetProviderRules sets provider rules directly (for testing or preloaded providers).
// This overrides any rules loaded via LoadProvider for the same name.
func (c *SliceConverter) SetProviderRules(name string, rules []string) {
	c.providerRules[name] = rules
}

// LoadProvider loads provider rules from content string.
// Supports both YAML "payload:" format and plain text (one rule per line).
func (c *SliceConverter) LoadProvider(name, content string) error {
	// Try YAML payload format first
	type payloadDoc struct {
		Payload []string `yaml:"payload"`
	}
	var doc payloadDoc
	if err := yaml.Unmarshal([]byte(content), &doc); err == nil && len(doc.Payload) > 0 {
		c.providerRules[name] = doc.Payload
		return nil
	}

	// Fall back to plain text format (one entry per line)
	var rules []string
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

// Convert parses a Clash YAML configuration and produces K2RULEV2 binary data.
func (c *SliceConverter) Convert(yamlContent string) ([]byte, error) {
	var config clashConfig
	if err := yaml.Unmarshal([]byte(yamlContent), &config); err != nil {
		return nil, err
	}

	var slices []*sliceData
	fallback := targetDirect

	for _, ruleStr := range config.Rules {
		parts := strings.Split(ruleStr, ",")
		if len(parts) < 2 {
			continue
		}

		ruleType := strings.TrimSpace(parts[0])
		targetStr := strings.TrimSpace(parts[len(parts)-1])
		target := parseTarget(targetStr)

		switch ruleType {
		case "DOMAIN":
			if len(parts) < 3 {
				continue
			}
			domain := strings.TrimSpace(parts[1])
			slices = appendOrMerge(slices, &sliceData{
				kind:    kindDomain,
				target:  target,
				domains: []string{domain},
			})

		case "DOMAIN-SUFFIX":
			if len(parts) < 3 {
				continue
			}
			suffix := strings.TrimSpace(parts[1])
			slices = appendOrMerge(slices, &sliceData{
				kind:    kindDomain,
				target:  target,
				domains: []string{suffix},
			})

		case "IP-CIDR":
			if len(parts) < 3 {
				continue
			}
			cidr := strings.TrimSpace(parts[1])
			network, prefixLen, ok := parseCIDRv4(cidr)
			if !ok {
				continue
			}
			slices = appendOrMerge(slices, &sliceData{
				kind:   kindCidrV4,
				target: target,
				cidrV4: [][2]uint32{{network, uint32(prefixLen)}},
			})

		case "IP-CIDR6":
			if len(parts) < 3 {
				continue
			}
			cidr := strings.TrimSpace(parts[1])
			network, prefixLen, ok := parseCIDRv6(cidr)
			if !ok {
				continue
			}
			slices = appendOrMerge(slices, &sliceData{
				kind:    kindCidrV6,
				target:  target,
				cidrV6N: [][16]byte{network},
				cidrV6P: []uint8{prefixLen},
			})

		case "GEOIP":
			if len(parts) < 3 {
				continue
			}
			country := strings.TrimSpace(parts[1])
			if strings.ToUpper(country) == "LAN" {
				addLANSlices(&slices, target)
			} else {
				slices = appendOrMerge(slices, &sliceData{
					kind:   kindGeoIP,
					target: target,
					geoips: []string{country},
				})
			}

		case "RULE-SET":
			if len(parts) < 3 {
				continue
			}
			providerName := strings.TrimSpace(parts[1])

			// Get behavior from config
			behavior := "domain"
			if p, ok := config.RuleProviders[providerName]; ok {
				behavior = p.Behavior
			}

			// Get rules: prefer externally loaded rules, then inline rules from config
			rules, ok := c.providerRules[providerName]
			if !ok {
				if p, ok2 := config.RuleProviders[providerName]; ok2 {
					rules = p.Rules
				}
			}

			c.addProviderSlices(&slices, behavior, rules, target)

		case "MATCH":
			fallback = target
		}
	}

	// Build binary using SliceWriter
	writer := slice.NewSliceWriter(fallback)
	for _, sd := range slices {
		if err := writeSliceData(writer, sd); err != nil {
			return nil, err
		}
	}
	return writer.Build()
}

// appendOrMerge appends a new sliceData to the list, merging with the last
// entry if they have the same kind and target.
func appendOrMerge(slices []*sliceData, sd *sliceData) []*sliceData {
	if len(slices) > 0 {
		last := slices[len(slices)-1]
		if last.canMerge(sd) {
			last.merge(sd)
			return slices
		}
	}
	return append(slices, sd)
}

// addProviderSlices expands a RULE-SET provider into sliceData entries.
func (c *SliceConverter) addProviderSlices(slices *[]*sliceData, behavior string, rules []string, target uint8) {
	switch strings.ToLower(behavior) {
	case "domain":
		var domains []string
		for _, rule := range rules {
			rule = strings.TrimSpace(rule)
			if rule == "" || strings.HasPrefix(rule, "#") {
				continue
			}
			// Convert Clash suffix format (+. or leading .) to plain domain
			if strings.HasPrefix(rule, "+.") {
				rule = rule[2:]
			} else if strings.HasPrefix(rule, ".") {
				rule = rule[1:]
			}
			domains = append(domains, rule)
		}
		if len(domains) > 0 {
			*slices = appendOrMerge(*slices, &sliceData{
				kind:    kindDomain,
				target:  target,
				domains: domains,
			})
		}

	case "ipcidr":
		var v4 [][2]uint32
		var v6N [][16]byte
		var v6P []uint8
		for _, rule := range rules {
			rule = strings.TrimSpace(rule)
			if rule == "" || strings.HasPrefix(rule, "#") {
				continue
			}
			if network, pfl, ok := parseCIDRv4(rule); ok {
				v4 = append(v4, [2]uint32{network, uint32(pfl)})
			} else if network6, pfl6, ok6 := parseCIDRv6(rule); ok6 {
				v6N = append(v6N, network6)
				v6P = append(v6P, pfl6)
			}
		}
		if len(v4) > 0 {
			*slices = appendOrMerge(*slices, &sliceData{
				kind:   kindCidrV4,
				target: target,
				cidrV4: v4,
			})
		}
		if len(v6N) > 0 {
			*slices = appendOrMerge(*slices, &sliceData{
				kind:    kindCidrV6,
				target:  target,
				cidrV6N: v6N,
				cidrV6P: v6P,
			})
		}

	case "classical":
		for _, rule := range rules {
			rule = strings.TrimSpace(rule)
			if rule == "" || strings.HasPrefix(rule, "#") {
				continue
			}
			c.parseClassicalRule(slices, rule, target)
		}
	}
}

// parseClassicalRule parses a single classical-format rule line and appends to slices.
func (c *SliceConverter) parseClassicalRule(slices *[]*sliceData, rule string, target uint8) {
	parts := strings.Split(rule, ",")
	if len(parts) < 2 {
		return
	}

	ruleType := strings.TrimSpace(parts[0])
	value := strings.TrimSpace(parts[1])

	switch ruleType {
	case "DOMAIN", "DOMAIN-SUFFIX":
		*slices = appendOrMerge(*slices, &sliceData{
			kind:    kindDomain,
			target:  target,
			domains: []string{value},
		})
	case "IP-CIDR":
		if network, pfl, ok := parseCIDRv4(value); ok {
			*slices = appendOrMerge(*slices, &sliceData{
				kind:   kindCidrV4,
				target: target,
				cidrV4: [][2]uint32{{network, uint32(pfl)}},
			})
		}
	case "IP-CIDR6":
		if network6, pfl6, ok := parseCIDRv6(value); ok {
			*slices = appendOrMerge(*slices, &sliceData{
				kind:    kindCidrV6,
				target:  target,
				cidrV6N: [][16]byte{network6},
				cidrV6P: []uint8{pfl6},
			})
		}
	case "GEOIP":
		if strings.ToUpper(value) == "LAN" {
			addLANSlices(slices, target)
		} else {
			*slices = appendOrMerge(*slices, &sliceData{
				kind:   kindGeoIP,
				target: target,
				geoips: []string{value},
			})
		}
	}
}

// addLANSlices expands the LAN GeoIP shortcut into IPv4 and IPv6 private ranges.
func addLANSlices(slices *[]*sliceData, target uint8) {
	// IPv4 private ranges: 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16
	*slices = appendOrMerge(*slices, &sliceData{
		kind:   kindCidrV4,
		target: target,
		cidrV4: [][2]uint32{
			{0x7F000000, 8},  // 127.0.0.0/8
			{0x0A000000, 8},  // 10.0.0.0/8
			{0xAC100000, 12}, // 172.16.0.0/12
			{0xC0A80000, 16}, // 192.168.0.0/16
			{0xA9FE0000, 16}, // 169.254.0.0/16
		},
	})

	// IPv6 private ranges: fc00::/7, fe80::/10, ::1/128
	fc00 := [16]byte{0xFC, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	fe80 := [16]byte{0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	loop := [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}

	*slices = appendOrMerge(*slices, &sliceData{
		kind:    kindCidrV6,
		target:  target,
		cidrV6N: [][16]byte{fc00, fe80, loop},
		cidrV6P: []uint8{7, 10, 128},
	})
}

// writeSliceData writes a sliceData entry to the SliceWriter.
func writeSliceData(w *slice.SliceWriter, sd *sliceData) error {
	switch sd.kind {
	case kindDomain:
		return w.AddDomainSlice(sd.domains, sd.target)
	case kindCidrV4:
		return w.AddCidrV4Slice(sd.cidrV4, sd.target)
	case kindCidrV6:
		return w.AddCidrV6SliceRaw(sd.cidrV6N, sd.cidrV6P, sd.target)
	case kindGeoIP:
		return w.AddGeoIPSlice(sd.geoips, sd.target)
	}
	return nil
}

// parseCIDRv4 parses an IPv4 CIDR string and returns (network_u32, prefix_len, ok).
func parseCIDRv4(cidr string) (uint32, uint8, bool) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return 0, 0, false
	}
	ip4 := ip.To4()
	if ip4 == nil {
		// Try network address
		ip4 = ipnet.IP.To4()
	}
	if ip4 == nil {
		return 0, 0, false
	}
	ones, bits := ipnet.Mask.Size()
	if bits != 32 {
		return 0, 0, false
	}
	network := binary.BigEndian.Uint32(ip4)
	// Mask to network address
	network = network & (^uint32(0) << uint(32-ones))
	return network, uint8(ones), true
}

// parseCIDRv6 parses an IPv6 CIDR string and returns (network_bytes, prefix_len, ok).
func parseCIDRv6(cidr string) ([16]byte, uint8, bool) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return [16]byte{}, 0, false
	}
	ip16 := ipnet.IP.To16()
	if ip16 == nil {
		return [16]byte{}, 0, false
	}
	ones, bits := ipnet.Mask.Size()
	if bits != 128 {
		return [16]byte{}, 0, false
	}
	var network [16]byte
	copy(network[:], ip16)
	return network, uint8(ones), true
}
