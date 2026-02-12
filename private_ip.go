package k2rule

import "net"

var (
	privateIPv4Ranges []*net.IPNet
	privateIPv6Ranges []*net.IPNet
)

func init() {
	parseCIDRs := func(cidrs []string) []*net.IPNet {
		ranges := make([]*net.IPNet, 0, len(cidrs))
		for _, cidr := range cidrs {
			_, ipnet, _ := net.ParseCIDR(cidr)
			ranges = append(ranges, ipnet)
		}
		return ranges
	}

	privateIPv4Ranges = parseCIDRs([]string{
		"10.0.0.0/8",       // Private network
		"172.16.0.0/12",    // Private network
		"192.168.0.0/16",   // Private network
		"127.0.0.0/8",      // Loopback
		"169.254.0.0/16",   // Link-local
	})

	privateIPv6Ranges = parseCIDRs([]string{
		"::1/128",   // Loopback
		"fe80::/10", // Link-local
		"fc00::/7",  // Unique local addresses (ULA)
	})
}

// isPrivateIP checks if an IP is in a private/LAN range (hardcoded).
// This function has the highest priority in Match() - private IPs always return DIRECT.
//
// IPv4 Private Ranges:
// - 10.0.0.0/8 - Private network
// - 172.16.0.0/12 - Private network
// - 192.168.0.0/16 - Private network
// - 127.0.0.0/8 - Loopback
// - 169.254.0.0/16 - Link-local
//
// IPv6 Private Ranges:
// - ::1/128 - Loopback
// - fe80::/10 - Link-local
// - fc00::/7 - Unique local addresses (ULA)
func isPrivateIP(ip net.IP) bool {
	if ip4 := ip.To4(); ip4 != nil {
		// Check IPv4 private ranges
		for _, ipnet := range privateIPv4Ranges {
			if ipnet.Contains(ip) {
				return true
			}
		}
		return false
	}

	// Check IPv6 private ranges
	for _, ipnet := range privateIPv6Ranges {
		if ipnet.Contains(ip) {
			return true
		}
	}
	return false
}

// IsPrivateIP is a public helper for checking if an IP string is private/LAN.
// Returns false if the input is not a valid IP address.
//
// Example:
//
//	if k2rule.IsPrivateIP("192.168.1.1") {
//	    fmt.Println("This is a LAN IP")
//	}
func IsPrivateIP(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	return isPrivateIP(parsed)
}
