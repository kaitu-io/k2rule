package k2rule

import (
	"net"
	"testing"
)

func TestIsPrivateIP_IPv4(t *testing.T) {
	tests := []struct {
		ip       string
		isPrivate bool
		desc     string
	}{
		// Private ranges
		{"10.0.0.1", true, "10.0.0.0/8 - Private network"},
		{"10.255.255.255", true, "10.0.0.0/8 - edge"},
		{"172.16.0.1", true, "172.16.0.0/12 - Private network"},
		{"172.31.255.255", true, "172.16.0.0/12 - edge"},
		{"192.168.0.1", true, "192.168.0.0/16 - Private network"},
		{"192.168.255.255", true, "192.168.0.0/16 - edge"},
		{"127.0.0.1", true, "127.0.0.0/8 - Loopback"},
		{"127.255.255.255", true, "127.0.0.0/8 - edge"},
		{"169.254.1.1", true, "169.254.0.0/16 - Link-local"},
		{"169.254.255.255", true, "169.254.0.0/16 - edge"},

		// Public IPs (not private)
		{"8.8.8.8", false, "Google DNS - public"},
		{"1.1.1.1", false, "Cloudflare DNS - public"},
		{"114.114.114.114", false, "China DNS - public"},
		{"172.15.0.1", false, "Just outside 172.16.0.0/12 range"},
		{"172.32.0.1", false, "Just outside 172.16.0.0/12 range"},
		{"11.0.0.1", false, "Just outside 10.0.0.0/8 range"},
		{"192.169.0.1", false, "Just outside 192.168.0.0/16 range"},
	}

	for _, tt := range tests {
		t.Run(tt.ip+" - "+tt.desc, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("Failed to parse IP: %s", tt.ip)
			}

			result := isPrivateIP(ip)
			if result != tt.isPrivate {
				t.Errorf("isPrivateIP(%s) = %v, want %v (%s)", tt.ip, result, tt.isPrivate, tt.desc)
			}
		})
	}
}

func TestIsPrivateIP_IPv6(t *testing.T) {
	tests := []struct {
		ip       string
		isPrivate bool
		desc     string
	}{
		// Private ranges
		{"::1", true, "::1/128 - Loopback"},
		{"fe80::1", true, "fe80::/10 - Link-local"},
		{"fe80::ffff:ffff:ffff:ffff", true, "fe80::/10 - Link-local edge"},
		{"fc00::1", true, "fc00::/7 - ULA"},
		{"fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", true, "fc00::/7 - ULA edge"},

		// Public IPs (not private)
		{"2001:4860:4860::8888", false, "Google DNS - public"},
		{"2606:4700:4700::1111", false, "Cloudflare DNS - public"},
		{"2400:3200::1", false, "Alibaba DNS - public"},
		{"2001:da8::666", false, "CERNET China - public"},
		{"fe00::1", false, "Just outside fe80::/10 range"},
		{"fb00::1", false, "Just outside fc00::/7 range"},
	}

	for _, tt := range tests {
		t.Run(tt.ip+" - "+tt.desc, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("Failed to parse IP: %s", tt.ip)
			}

			result := isPrivateIP(ip)
			if result != tt.isPrivate {
				t.Errorf("isPrivateIP(%s) = %v, want %v (%s)", tt.ip, result, tt.isPrivate, tt.desc)
			}
		})
	}
}

func TestIsPrivateIP_PublicHelper(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
		desc     string
	}{
		// Valid private IPs
		{"192.168.1.1", true, "Private IPv4"},
		{"10.0.0.1", true, "Private IPv4"},
		{"::1", true, "Private IPv6"},
		{"fe80::1", true, "Link-local IPv6"},

		// Valid public IPs
		{"8.8.8.8", false, "Public IPv4"},
		{"2001:4860:4860::8888", false, "Public IPv6"},

		// Invalid IPs
		{"invalid", false, "Invalid IP string"},
		{"256.256.256.256", false, "Invalid IPv4"},
		{"", false, "Empty string"},
	}

	for _, tt := range tests {
		t.Run(tt.input+" - "+tt.desc, func(t *testing.T) {
			result := IsPrivateIP(tt.input)
			if result != tt.expected {
				t.Errorf("IsPrivateIP(%s) = %v, want %v (%s)", tt.input, result, tt.expected, tt.desc)
			}
		})
	}
}
