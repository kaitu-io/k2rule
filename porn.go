package k2rule

import (
	"github.com/kaitu-io/k2rule/internal/porn"
)

// PornChecker provides porn domain detection using both heuristic and FST methods
type PornChecker struct {
	fst *porn.FSTChecker
}

// NewPornChecker creates a new porn checker with heuristic-only detection
func NewPornChecker() *PornChecker {
	return &PornChecker{}
}

// NewPornCheckerFromFile creates a porn checker with both heuristic and FST detection
func NewPornCheckerFromFile(fstPath string) (*PornChecker, error) {
	fst, err := porn.NewFSTCheckerFromFile(fstPath)
	if err != nil {
		return nil, err
	}

	return &PornChecker{
		fst: fst,
	}, nil
}

// NewPornCheckerFromBytes creates a porn checker from FST bytes
func NewPornCheckerFromBytes(fstData []byte) (*PornChecker, error) {
	fst, err := porn.NewFSTCheckerFromBytes(fstData)
	if err != nil {
		return nil, err
	}

	return &PornChecker{
		fst: fst,
	}, nil
}

// NewPornCheckerFromGzip creates a porn checker from gzip-compressed FST bytes
func NewPornCheckerFromGzip(gzipData []byte) (*PornChecker, error) {
	fst, err := porn.NewFSTCheckerFromGzip(gzipData)
	if err != nil {
		return nil, err
	}

	return &PornChecker{
		fst: fst,
	}, nil
}

// IsPorn checks if a domain is a porn domain
//
// Detection flow:
//  1. Quick heuristic check (8 layers, no I/O)
//  2. FST query (if FST is loaded and heuristic didn't match)
func (c *PornChecker) IsPorn(domain string) bool {
	// Layer 1: Fast heuristic detection
	if porn.IsPornHeuristic(domain) {
		return true
	}

	// Layer 2: FST lookup (if available)
	if c.fst != nil {
		return c.fst.IsPorn(domain)
	}

	return false
}

// IsPornHeuristic checks if a domain matches porn heuristic patterns
// This is a fast, I/O-free check using 8 layers of pattern matching
func IsPornHeuristic(domain string) bool {
	return porn.IsPornHeuristic(domain)
}
