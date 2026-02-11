package k2rule

import "fmt"

// Target represents the routing decision for a request
type Target uint8

const (
	// TargetDirect routes traffic directly without proxy
	TargetDirect Target = 0
	// TargetProxy routes traffic through proxy
	TargetProxy Target = 1
	// TargetReject blocks the traffic
	TargetReject Target = 2
)

// String returns the string representation of Target
func (t Target) String() string {
	switch t {
	case TargetDirect:
		return "DIRECT"
	case TargetProxy:
		return "PROXY"
	case TargetReject:
		return "REJECT"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", t)
	}
}

// ParseTarget parses a string into Target
func ParseTarget(s string) (Target, error) {
	switch s {
	case "DIRECT", "direct":
		return TargetDirect, nil
	case "PROXY", "proxy":
		return TargetProxy, nil
	case "REJECT", "reject":
		return TargetReject, nil
	default:
		return 0, fmt.Errorf("invalid target: %s", s)
	}
}
