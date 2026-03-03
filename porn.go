package k2rule

import (
	"github.com/kaitu-io/k2rule/internal/porn"
	"github.com/kaitu-io/k2rule/internal/slice"
)

// PornChecker provides porn domain detection using both heuristic and CachedMmapReader methods.
// Uses mmap for zero-copy access — rule data lives in OS page cache, not Go heap.
type PornChecker struct {
	reader *slice.CachedMmapReader
}

// NewPornChecker creates a new porn checker with heuristic-only detection
func NewPornChecker() *PornChecker {
	return &PornChecker{}
}

// NewPornCheckerFromFile creates a porn checker with both heuristic and mmap-based detection.
// The file must be in K2RULEV3 format (.k2r.gz gzip compressed).
func NewPornCheckerFromFile(path string) (*PornChecker, error) {
	reader := slice.NewCachedMmapReader()
	if err := reader.Load(path); err != nil {
		return nil, err
	}
	return &PornChecker{reader: reader}, nil
}

// IsPorn checks if a domain is a porn domain.
//
// Detection flow:
//  1. Quick heuristic check (8 layers, no I/O)
//  2. CachedMmapReader query (zero-copy mmap lookup, if loaded)
//
// A target value of 2 means Reject (porn blocked).
func (c *PornChecker) IsPorn(domain string) bool {
	// Layer 1: Fast heuristic detection
	if porn.IsPornHeuristic(domain) {
		return true
	}

	// Layer 2: Mmap-based K2RULEV3 lookup (if available)
	if c.reader != nil {
		if target := c.reader.MatchDomain(domain); target != nil {
			return *target == 2 // targetReject
		}
	}

	return false
}

// Close releases the mmap resources held by this checker.
func (c *PornChecker) Close() error {
	if c.reader != nil {
		return c.reader.Close()
	}
	return nil
}

// IsPornHeuristic checks if a domain matches porn heuristic patterns.
// This is a fast, I/O-free check using 8 layers of pattern matching.
func IsPornHeuristic(domain string) bool {
	return porn.IsPornHeuristic(domain)
}
