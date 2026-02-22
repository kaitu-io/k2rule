package k2rule

import (
	"github.com/kaitu-io/k2rule/internal/porn"
	"github.com/kaitu-io/k2rule/internal/slice"
)

// PornChecker provides porn domain detection using both heuristic and SliceReader methods
type PornChecker struct {
	reader *slice.SliceReader
}

// NewPornChecker creates a new porn checker with heuristic-only detection
func NewPornChecker() *PornChecker {
	return &PornChecker{}
}

// NewPornCheckerFromFile creates a porn checker with both heuristic and SliceReader detection.
// The file must be in K2RULEV2 format (.k2r or .k2r.gz); gzip is auto-detected.
func NewPornCheckerFromFile(path string) (*PornChecker, error) {
	reader, err := slice.NewSliceReaderFromFile(path)
	if err != nil {
		return nil, err
	}

	return &PornChecker{
		reader: reader,
	}, nil
}

// IsPorn checks if a domain is a porn domain.
//
// Detection flow:
//  1. Quick heuristic check (8 layers, no I/O)
//  2. SliceReader query (if loaded and heuristic didn't match)
//
// In the SliceReader, a target value of 2 means Reject (porn blocked).
func (c *PornChecker) IsPorn(domain string) bool {
	// Layer 1: Fast heuristic detection
	if porn.IsPornHeuristic(domain) {
		return true
	}

	// Layer 2: SliceReader lookup (if available)
	if c.reader != nil {
		if target := c.reader.MatchDomain(domain); target != nil {
			return *target == 2 // targetReject
		}
	}

	return false
}

// IsPornHeuristic checks if a domain matches porn heuristic patterns.
// This is a fast, I/O-free check using 8 layers of pattern matching.
func IsPornHeuristic(domain string) bool {
	return porn.IsPornHeuristic(domain)
}
