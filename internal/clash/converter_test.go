package clash_test

import (
	"net"
	"testing"

	"github.com/kaitu-io/k2rule/internal/clash"
	"github.com/kaitu-io/k2rule/internal/slice"
)

// Target constants matching the existing Go codebase
const (
	targetDirect uint8 = 0
	targetProxy  uint8 = 1
	targetReject uint8 = 2
)

func ptrUint8(v uint8) *uint8 { return &v }

func mustParseIP(s string) net.IP {
	ip := net.ParseIP(s)
	if ip == nil {
		panic("failed to parse IP: " + s)
	}
	return ip
}

// TestConverterSimpleRules verifies DOMAIN, DOMAIN-SUFFIX, GEOIP, MATCH rules.
func TestConverterSimpleRules(t *testing.T) {
	yaml := `
rules:
  - DOMAIN,google.com,PROXY
  - DOMAIN-SUFFIX,youtube.com,PROXY
  - GEOIP,CN,DIRECT
  - MATCH,PROXY
`
	converter := clash.NewSliceConverter()
	data, err := converter.Convert(yaml)
	if err != nil {
		t.Fatalf("Convert failed: %v", err)
	}

	reader, err := slice.NewSliceReaderFromBytes(data)
	if err != nil {
		t.Fatalf("NewSliceReaderFromBytes failed: %v", err)
	}

	// Fallback should be Proxy
	if got := reader.Fallback(); got != targetProxy {
		t.Errorf("fallback: got %d, want %d", got, targetProxy)
	}

	t.Run("google.com→Proxy", func(t *testing.T) {
		got := reader.MatchDomain("google.com")
		if got == nil || *got != targetProxy {
			t.Errorf("MatchDomain(google.com): got %v, want %d", got, targetProxy)
		}
	})

	t.Run("youtube.com→Proxy", func(t *testing.T) {
		got := reader.MatchDomain("youtube.com")
		if got == nil || *got != targetProxy {
			t.Errorf("MatchDomain(youtube.com): got %v, want %d", got, targetProxy)
		}
	})

	t.Run("www.youtube.com→Proxy", func(t *testing.T) {
		got := reader.MatchDomain("www.youtube.com")
		if got == nil || *got != targetProxy {
			t.Errorf("MatchDomain(www.youtube.com): got %v, want %d", got, targetProxy)
		}
	})

	t.Run("GeoIP CN→Direct", func(t *testing.T) {
		got := reader.MatchGeoIP("CN")
		if got == nil || *got != targetDirect {
			t.Errorf("MatchGeoIP(CN): got %v, want %d", got, targetDirect)
		}
	})
}

// TestConverterRuleProviders verifies domain behavior providers with inline rules.
func TestConverterRuleProviders(t *testing.T) {
	yaml := `
rule-providers:
  proxy-domains:
    type: http
    behavior: domain
    rules:
      - google.com
      - "+.googleapis.com"

rules:
  - RULE-SET,proxy-domains,PROXY
  - MATCH,DIRECT
`
	converter := clash.NewSliceConverter()
	data, err := converter.Convert(yaml)
	if err != nil {
		t.Fatalf("Convert failed: %v", err)
	}

	reader, err := slice.NewSliceReaderFromBytes(data)
	if err != nil {
		t.Fatalf("NewSliceReaderFromBytes failed: %v", err)
	}

	// Fallback should be Direct
	if got := reader.Fallback(); got != targetDirect {
		t.Errorf("fallback: got %d, want %d", got, targetDirect)
	}

	t.Run("google.com→Proxy", func(t *testing.T) {
		got := reader.MatchDomain("google.com")
		if got == nil || *got != targetProxy {
			t.Errorf("MatchDomain(google.com): got %v, want %d", got, targetProxy)
		}
	})

	t.Run("www.googleapis.com→Proxy", func(t *testing.T) {
		got := reader.MatchDomain("www.googleapis.com")
		if got == nil || *got != targetProxy {
			t.Errorf("MatchDomain(www.googleapis.com): got %v, want %d", got, targetProxy)
		}
	})
}

// TestConverterMergeAdjacentSlices verifies that adjacent same-type same-target slices are merged.
func TestConverterMergeAdjacentSlices(t *testing.T) {
	yaml := `
rules:
  - DOMAIN,a.com,PROXY
  - DOMAIN,b.com,PROXY
  - DOMAIN,c.com,DIRECT
  - DOMAIN,d.com,PROXY
  - MATCH,DIRECT
`
	converter := clash.NewSliceConverter()
	data, err := converter.Convert(yaml)
	if err != nil {
		t.Fatalf("Convert failed: %v", err)
	}

	reader, err := slice.NewSliceReaderFromBytes(data)
	if err != nil {
		t.Fatalf("NewSliceReaderFromBytes failed: %v", err)
	}

	// a.com and b.com merged → 1 slice, c.com → 1 slice, d.com → 1 slice = 3 slices total
	if got := reader.SliceCount(); got != 3 {
		t.Errorf("SliceCount: got %d, want 3", got)
	}

	t.Run("a.com→Proxy", func(t *testing.T) {
		got := reader.MatchDomain("a.com")
		if got == nil || *got != targetProxy {
			t.Errorf("MatchDomain(a.com): got %v, want %d", got, targetProxy)
		}
	})

	t.Run("b.com→Proxy", func(t *testing.T) {
		got := reader.MatchDomain("b.com")
		if got == nil || *got != targetProxy {
			t.Errorf("MatchDomain(b.com): got %v, want %d", got, targetProxy)
		}
	})

	t.Run("c.com→Direct", func(t *testing.T) {
		got := reader.MatchDomain("c.com")
		if got == nil || *got != targetDirect {
			t.Errorf("MatchDomain(c.com): got %v, want %d", got, targetDirect)
		}
	})

	t.Run("d.com→Proxy", func(t *testing.T) {
		got := reader.MatchDomain("d.com")
		if got == nil || *got != targetProxy {
			t.Errorf("MatchDomain(d.com): got %v, want %d", got, targetProxy)
		}
	})
}

// TestConverterOrderingPreserved verifies that rule order is maintained (first match wins).
func TestConverterOrderingPreserved(t *testing.T) {
	yaml := `
rules:
  - DOMAIN-SUFFIX,cn.bing.com,DIRECT
  - DOMAIN-SUFFIX,bing.com,PROXY
  - MATCH,DIRECT
`
	converter := clash.NewSliceConverter()
	data, err := converter.Convert(yaml)
	if err != nil {
		t.Fatalf("Convert failed: %v", err)
	}

	reader, err := slice.NewSliceReaderFromBytes(data)
	if err != nil {
		t.Fatalf("NewSliceReaderFromBytes failed: %v", err)
	}

	t.Run("cn.bing.com→Direct", func(t *testing.T) {
		got := reader.MatchDomain("cn.bing.com")
		if got == nil || *got != targetDirect {
			t.Errorf("MatchDomain(cn.bing.com): got %v, want %d", got, targetDirect)
		}
	})

	t.Run("www.cn.bing.com→Direct", func(t *testing.T) {
		got := reader.MatchDomain("www.cn.bing.com")
		if got == nil || *got != targetDirect {
			t.Errorf("MatchDomain(www.cn.bing.com): got %v, want %d", got, targetDirect)
		}
	})

	t.Run("bing.com→Proxy", func(t *testing.T) {
		got := reader.MatchDomain("bing.com")
		if got == nil || *got != targetProxy {
			t.Errorf("MatchDomain(bing.com): got %v, want %d", got, targetProxy)
		}
	})

	t.Run("www.bing.com→Proxy", func(t *testing.T) {
		got := reader.MatchDomain("www.bing.com")
		if got == nil || *got != targetProxy {
			t.Errorf("MatchDomain(www.bing.com): got %v, want %d", got, targetProxy)
		}
	})
}

// TestConverterCidrRules verifies IP-CIDR and IP-CIDR6 rules.
func TestConverterCidrRules(t *testing.T) {
	yaml := `
rules:
  - IP-CIDR,10.0.0.0/8,DIRECT
  - IP-CIDR6,fc00::/7,DIRECT
  - MATCH,PROXY
`
	converter := clash.NewSliceConverter()
	data, err := converter.Convert(yaml)
	if err != nil {
		t.Fatalf("Convert failed: %v", err)
	}

	reader, err := slice.NewSliceReaderFromBytes(data)
	if err != nil {
		t.Fatalf("NewSliceReaderFromBytes failed: %v", err)
	}

	t.Run("10.1.2.3→Direct", func(t *testing.T) {
		got := reader.MatchIP(mustParseIP("10.1.2.3"))
		if got == nil || *got != targetDirect {
			t.Errorf("MatchIP(10.1.2.3): got %v, want %d", got, targetDirect)
		}
	})

	t.Run("fc00::1→Direct", func(t *testing.T) {
		got := reader.MatchIP(mustParseIP("fc00::1"))
		if got == nil || *got != targetDirect {
			t.Errorf("MatchIP(fc00::1): got %v, want %d", got, targetDirect)
		}
	})

	t.Run("8.8.8.8→nil", func(t *testing.T) {
		got := reader.MatchIP(mustParseIP("8.8.8.8"))
		if got != nil {
			t.Errorf("MatchIP(8.8.8.8): got %v, want nil (use fallback)", got)
		}
	})
}

// TestConverterLanGeoIP verifies GEOIP,LAN,DIRECT expands to private ranges.
func TestConverterLanGeoIP(t *testing.T) {
	yaml := `
rules:
  - GEOIP,LAN,DIRECT
  - MATCH,PROXY
`
	converter := clash.NewSliceConverter()
	data, err := converter.Convert(yaml)
	if err != nil {
		t.Fatalf("Convert failed: %v", err)
	}

	reader, err := slice.NewSliceReaderFromBytes(data)
	if err != nil {
		t.Fatalf("NewSliceReaderFromBytes failed: %v", err)
	}

	t.Run("10.0.0.1→Direct", func(t *testing.T) {
		got := reader.MatchIP(mustParseIP("10.0.0.1"))
		if got == nil || *got != targetDirect {
			t.Errorf("MatchIP(10.0.0.1): got %v, want %d", got, targetDirect)
		}
	})

	t.Run("192.168.1.1→Direct", func(t *testing.T) {
		got := reader.MatchIP(mustParseIP("192.168.1.1"))
		if got == nil || *got != targetDirect {
			t.Errorf("MatchIP(192.168.1.1): got %v, want %d", got, targetDirect)
		}
	})

	t.Run("fc00::1→Direct", func(t *testing.T) {
		got := reader.MatchIP(mustParseIP("fc00::1"))
		if got == nil || *got != targetDirect {
			t.Errorf("MatchIP(fc00::1): got %v, want %d", got, targetDirect)
		}
	})
}

// TestConverterExternalProvider verifies SetProviderRules for external providers.
func TestConverterExternalProvider(t *testing.T) {
	yaml := `
rule-providers:
  external:
    type: http
    behavior: domain
    url: https://example.com/rules.yaml

rules:
  - RULE-SET,external,PROXY
  - MATCH,DIRECT
`
	converter := clash.NewSliceConverter()
	converter.SetProviderRules("external", []string{"google.com", "youtube.com"})

	data, err := converter.Convert(yaml)
	if err != nil {
		t.Fatalf("Convert failed: %v", err)
	}

	reader, err := slice.NewSliceReaderFromBytes(data)
	if err != nil {
		t.Fatalf("NewSliceReaderFromBytes failed: %v", err)
	}

	t.Run("google.com→Proxy", func(t *testing.T) {
		got := reader.MatchDomain("google.com")
		if got == nil || *got != targetProxy {
			t.Errorf("MatchDomain(google.com): got %v, want %d", got, targetProxy)
		}
	})

	t.Run("youtube.com→Proxy", func(t *testing.T) {
		got := reader.MatchDomain("youtube.com")
		if got == nil || *got != targetProxy {
			t.Errorf("MatchDomain(youtube.com): got %v, want %d", got, targetProxy)
		}
	})
}

// TestConverterIpcidrProvider verifies ipcidr behavior providers.
func TestConverterIpcidrProvider(t *testing.T) {
	yaml := `
rule-providers:
  private:
    type: http
    behavior: ipcidr
    rules:
      - 10.0.0.0/8
      - 172.16.0.0/12

rules:
  - RULE-SET,private,DIRECT
  - MATCH,PROXY
`
	converter := clash.NewSliceConverter()
	data, err := converter.Convert(yaml)
	if err != nil {
		t.Fatalf("Convert failed: %v", err)
	}

	reader, err := slice.NewSliceReaderFromBytes(data)
	if err != nil {
		t.Fatalf("NewSliceReaderFromBytes failed: %v", err)
	}

	t.Run("10.1.2.3→Direct", func(t *testing.T) {
		got := reader.MatchIP(mustParseIP("10.1.2.3"))
		if got == nil || *got != targetDirect {
			t.Errorf("MatchIP(10.1.2.3): got %v, want %d", got, targetDirect)
		}
	})

	t.Run("172.20.0.1→Direct", func(t *testing.T) {
		got := reader.MatchIP(mustParseIP("172.20.0.1"))
		if got == nil || *got != targetDirect {
			t.Errorf("MatchIP(172.20.0.1): got %v, want %d", got, targetDirect)
		}
	})
}

// TestConverterClassicalProvider verifies classical behavior with mixed rule types.
func TestConverterClassicalProvider(t *testing.T) {
	yaml := `
rule-providers:
  mixed:
    type: http
    behavior: classical
    rules:
      - DOMAIN,google.com
      - IP-CIDR,10.0.0.0/8

rules:
  - RULE-SET,mixed,PROXY
  - MATCH,DIRECT
`
	converter := clash.NewSliceConverter()
	data, err := converter.Convert(yaml)
	if err != nil {
		t.Fatalf("Convert failed: %v", err)
	}

	reader, err := slice.NewSliceReaderFromBytes(data)
	if err != nil {
		t.Fatalf("NewSliceReaderFromBytes failed: %v", err)
	}

	t.Run("google.com→Proxy", func(t *testing.T) {
		got := reader.MatchDomain("google.com")
		if got == nil || *got != targetProxy {
			t.Errorf("MatchDomain(google.com): got %v, want %d", got, targetProxy)
		}
	})

	t.Run("10.1.2.3→Proxy", func(t *testing.T) {
		got := reader.MatchIP(mustParseIP("10.1.2.3"))
		if got == nil || *got != targetProxy {
			t.Errorf("MatchIP(10.1.2.3): got %v, want %d", got, targetProxy)
		}
	})
}

// TestConverterProviderPayloadParsing verifies both YAML payload: format and plain text.
func TestConverterProviderPayloadParsing(t *testing.T) {
	converter := clash.NewSliceConverter()

	t.Run("YAML payload format", func(t *testing.T) {
		yamlContent := `payload:
  - google.com
  - youtube.com
`
		err := converter.LoadProvider("test-yaml", yamlContent)
		if err != nil {
			t.Fatalf("LoadProvider YAML failed: %v", err)
		}

		clashConfig := `
rule-providers:
  test-yaml:
    behavior: domain
    type: http
    url: https://example.com

rules:
  - RULE-SET,test-yaml,PROXY
  - MATCH,DIRECT
`
		data, err := converter.Convert(clashConfig)
		if err != nil {
			t.Fatalf("Convert failed: %v", err)
		}

		reader, err := slice.NewSliceReaderFromBytes(data)
		if err != nil {
			t.Fatalf("NewSliceReaderFromBytes failed: %v", err)
		}

		got := reader.MatchDomain("google.com")
		if got == nil || *got != targetProxy {
			t.Errorf("MatchDomain(google.com): got %v, want %d", got, targetProxy)
		}

		got = reader.MatchDomain("youtube.com")
		if got == nil || *got != targetProxy {
			t.Errorf("MatchDomain(youtube.com): got %v, want %d", got, targetProxy)
		}
	})

	t.Run("plain text format", func(t *testing.T) {
		plainText := `google.com
youtube.com
`
		err := converter.LoadProvider("test-plain", plainText)
		if err != nil {
			t.Fatalf("LoadProvider plain failed: %v", err)
		}

		clashConfig := `
rule-providers:
  test-plain:
    behavior: domain
    type: http
    url: https://example.com

rules:
  - RULE-SET,test-plain,PROXY
  - MATCH,DIRECT
`
		data, err := converter.Convert(clashConfig)
		if err != nil {
			t.Fatalf("Convert failed: %v", err)
		}

		reader, err := slice.NewSliceReaderFromBytes(data)
		if err != nil {
			t.Fatalf("NewSliceReaderFromBytes failed: %v", err)
		}

		got := reader.MatchDomain("google.com")
		if got == nil || *got != targetProxy {
			t.Errorf("MatchDomain(google.com): got %v, want %d", got, targetProxy)
		}
	})
}
