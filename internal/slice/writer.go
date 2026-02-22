package slice

import (
	"encoding/binary"
	"fmt"
	"sort"
	"time"
)

// SliceWriter builds K2RULEV2 binary format data.
type SliceWriter struct {
	fallback uint8
	slices   []sliceWriterEntry
}

type sliceWriterEntry struct {
	sliceType uint8
	target    uint8
	count     uint32
	data      []byte
}

// NewSliceWriter creates a new SliceWriter with the given fallback target.
func NewSliceWriter(fallback uint8) *SliceWriter {
	return &SliceWriter{fallback: fallback}
}

// AddDomainSlice adds a domain (FST) slice.
// Domains are stored reversed with a leading dot for suffix matching.
func (w *SliceWriter) AddDomainSlice(domains []string, target uint8) error {
	if len(domains) == 0 {
		return nil
	}

	// Normalize: lowercase, add leading dot if missing, reverse
	reversed := make([]string, 0, len(domains))
	for _, d := range domains {
		lower := strToLower(d)
		var withDot string
		if len(lower) > 0 && lower[0] == '.' {
			withDot = lower
		} else {
			withDot = "." + lower
		}
		reversed = append(reversed, strReverse(withDot))
	}

	sort.Strings(reversed)
	reversed = dedupStrings(reversed)

	fstData, err := buildFSTSet(reversed)
	if err != nil {
		return err
	}

	w.slices = append(w.slices, sliceWriterEntry{
		sliceType: uint8(SliceTypeFstDomain),
		target:    target,
		count:     uint32(len(reversed)),
		data:      fstData,
	})
	return nil
}

// AddCidrV4Slice adds an IPv4 CIDR slice.
// Each cidr is [network_u32, prefix_len] where network is a host-order uint32.
func (w *SliceWriter) AddCidrV4Slice(cidrs [][2]uint32, target uint8) error {
	if len(cidrs) == 0 {
		return nil
	}

	sorted := make([][2]uint32, len(cidrs))
	copy(sorted, cidrs)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i][0] < sorted[j][0]
	})

	// Each entry: network (4 bytes BE) + prefix_len (1 byte) + padding (3 bytes) = 8 bytes
	data := make([]byte, len(sorted)*8)
	for i, cidr := range sorted {
		binary.BigEndian.PutUint32(data[i*8:], cidr[0])
		data[i*8+4] = uint8(cidr[1])
	}

	w.slices = append(w.slices, sliceWriterEntry{
		sliceType: uint8(SliceTypeCidrV4),
		target:    target,
		count:     uint32(len(sorted)),
		data:      data,
	})
	return nil
}

// AddCidrV6SliceRaw adds an IPv6 CIDR slice.
// networks and prefixLens must have the same length.
func (w *SliceWriter) AddCidrV6SliceRaw(networks [][16]byte, prefixLens []uint8, target uint8) error {
	if len(networks) == 0 {
		return nil
	}
	if len(networks) != len(prefixLens) {
		return fmt.Errorf("networks and prefixLens length mismatch: %d vs %d", len(networks), len(prefixLens))
	}

	type entry struct {
		net [16]byte
		pfl uint8
	}
	sorted := make([]entry, len(networks))
	for i := range networks {
		sorted[i] = entry{networks[i], prefixLens[i]}
	}
	sort.Slice(sorted, func(i, j int) bool {
		for k := 0; k < 16; k++ {
			if sorted[i].net[k] != sorted[j].net[k] {
				return sorted[i].net[k] < sorted[j].net[k]
			}
		}
		return false
	})

	// Each entry: network (16 bytes) + prefix_len (1 byte) + padding (7 bytes) = 24 bytes
	data := make([]byte, len(sorted)*24)
	for i, e := range sorted {
		copy(data[i*24:], e.net[:])
		data[i*24+16] = e.pfl
	}

	w.slices = append(w.slices, sliceWriterEntry{
		sliceType: uint8(SliceTypeCidrV6),
		target:    target,
		count:     uint32(len(sorted)),
		data:      data,
	})
	return nil
}

// AddGeoIPSlice adds a GeoIP country code slice.
func (w *SliceWriter) AddGeoIPSlice(countries []string, target uint8) error {
	if len(countries) == 0 {
		return nil
	}

	// Each entry: country_code (2 bytes) + padding (2 bytes) = 4 bytes
	data := make([]byte, len(countries)*4)
	for i, country := range countries {
		upper := strToUpper(country)
		bs := []byte(upper)
		if len(bs) >= 1 {
			data[i*4] = bs[0]
		}
		if len(bs) >= 2 {
			data[i*4+1] = bs[1]
		}
	}

	w.slices = append(w.slices, sliceWriterEntry{
		sliceType: uint8(SliceTypeGeoIP),
		target:    target,
		count:     uint32(len(countries)),
		data:      data,
	})
	return nil
}

// Build assembles the final binary output.
func (w *SliceWriter) Build() ([]byte, error) {
	sliceCount := len(w.slices)
	indexSize := sliceCount * EntrySize
	dataStart := HeaderSize + indexSize

	currentOffset := dataStart
	offsets := make([]int, sliceCount)
	for i, s := range w.slices {
		offsets[i] = currentOffset
		currentOffset += len(s.data)
	}

	totalSize := currentOffset
	output := make([]byte, totalSize)

	// Write header (64 bytes):
	// Magic[8] Version[4] SliceCount[4] Fallback[1] _reserved1[3] Timestamp[8] Checksum[16] _reserved2[16] = 60
	// + 4 bytes pad to reach HeaderSize=64
	copy(output[0:8], []byte(Magic))
	binary.LittleEndian.PutUint32(output[8:12], FormatVersion)
	binary.LittleEndian.PutUint32(output[12:16], uint32(sliceCount))
	output[16] = w.fallback
	// bytes 17-19: _reserved1 = 0
	ts := time.Now().Unix()
	binary.LittleEndian.PutUint64(output[20:28], uint64(ts))
	// bytes 28-43: checksum = 0
	// bytes 44-59: _reserved2 = 0
	// bytes 60-63: pad = 0

	// Write slice index
	for i, s := range w.slices {
		base := HeaderSize + i*EntrySize
		output[base] = s.sliceType
		output[base+1] = s.target
		// bytes base+2, base+3: reserved = 0
		binary.LittleEndian.PutUint32(output[base+4:], uint32(offsets[i]))
		binary.LittleEndian.PutUint32(output[base+8:], uint32(len(s.data)))
		binary.LittleEndian.PutUint32(output[base+12:], s.count)
	}

	// Write slice data
	for i, s := range w.slices {
		copy(output[offsets[i]:], s.data)
	}

	return output, nil
}

// ============================================================================
// FST Set Builder (Rust fst v3 compatible)
// ============================================================================

// buildFSTSet builds a Rust-fst-v3-compatible FST Set from sorted, deduplicated keys.
func buildFSTSet(keys []string) ([]byte, error) {
	if len(keys) == 0 {
		return buildEmptyFST(), nil
	}
	b := newFSTSetBuilder()
	for _, k := range keys {
		b.insert([]byte(k))
	}
	return b.finish(), nil
}

// buildEmptyFST creates a minimal empty FST.
func buildEmptyFST() []byte {
	// Root node: 0 transitions, not final
	data := []byte{0x00}
	return fstAppendFooter(data, 0)
}

// fstAppendFooter appends the 36-byte Rust fst v3 footer.
// Footer layout: version(u64) type(u64) root_addr(u64) len(u64) checksum(u32)
func fstAppendFooter(data []byte, rootAddr uint64) []byte {
	nodeLen := uint64(len(data))
	footer := make([]byte, 36)
	binary.LittleEndian.PutUint64(footer[0:8], uint64(fstVersion)) // version = 3
	binary.LittleEndian.PutUint64(footer[8:16], 0)                 // type = 0 (set)
	binary.LittleEndian.PutUint64(footer[16:24], rootAddr)
	binary.LittleEndian.PutUint64(footer[24:32], nodeLen)
	// checksum [32:36] = 0
	return append(data, footer...)
}

// fstSetBuilder builds a Rust-fst-compatible Set.
//
// The algorithm (Lempel-Ziv-like suffix sharing):
//  1. Insert sorted keys one at a time
//  2. For each key, find the common prefix with the previous key
//  3. Compile ("freeze") nodes that are deeper than the common prefix — they won't get new transitions
//  4. Compiled nodes are deduplicated by canonical content (suffix sharing)
//  5. After all keys, compile remaining nodes and the root
type fstSetBuilder struct {
	buf     []byte            // output buffer for compiled node bytes
	stack   []*fstBNode       // working stack: stack[depth] = node being built
	cache   map[string]uint64 // canonical encoding -> address in buf
	lastKey []byte
}

// fstBNode is a node being built (not yet compiled).
type fstBNode struct {
	isFinal     bool
	transitions []fstBTrans
}

// fstBTrans is a transition in a node being built.
type fstBTrans struct {
	inp  byte
	addr uint64 // address of compiled child (set after child is frozen)
}

func newFSTSetBuilder() *fstSetBuilder {
	b := &fstSetBuilder{
		buf:   make([]byte, 0, 512),
		cache: make(map[string]uint64),
	}
	// Root node at depth 0
	b.stack = []*fstBNode{{}}
	return b
}

// insert adds a key to the builder. Keys must be in lexicographic order.
func (b *fstSetBuilder) insert(key []byte) {
	// Find common prefix length with last key
	cp := 0
	for cp < len(b.lastKey) && cp < len(key) && b.lastKey[cp] == key[cp] {
		cp++
	}

	// Freeze nodes at depths > cp (they won't get more transitions)
	b.freeze(cp + 1)

	// Add transitions for the new suffix (key[cp:])
	for i := cp; i < len(key); i++ {
		depth := i + 1
		// Grow stack if needed
		for len(b.stack) <= depth {
			b.stack = append(b.stack, &fstBNode{})
		}
		// Reset child node at this depth
		b.stack[depth] = &fstBNode{}
		// Add transition from parent (depth i) to child (depth i+1)
		b.stack[i].transitions = append(b.stack[i].transitions, fstBTrans{inp: key[i]})
	}

	// Mark node at depth len(key) as final
	depth := len(key)
	for len(b.stack) <= depth {
		b.stack = append(b.stack, &fstBNode{})
	}
	b.stack[depth].isFinal = true

	b.lastKey = append(b.lastKey[:0], key...)
}

// freeze compiles all nodes in the stack from depth `from` to end.
// After freezing, the stack is trimmed to length `max(1, from)`.
func (b *fstSetBuilder) freeze(from int) {
	for depth := len(b.stack) - 1; depth >= from; depth-- {
		node := b.stack[depth]
		if node == nil {
			continue
		}
		addr := b.compileNode(node)
		b.stack[depth] = nil

		// Wire up the parent's last transition to this compiled address
		if depth > 0 {
			parent := b.stack[depth-1]
			if parent != nil && len(parent.transitions) > 0 {
				parent.transitions[len(parent.transitions)-1].addr = addr
			}
		}
	}

	// Trim stack to `from` (keep at least root)
	keepLen := from
	if keepLen < 1 {
		keepLen = 1
	}
	if keepLen < len(b.stack) {
		b.stack = b.stack[:keepLen]
	}
}

// compileNode writes a node to the buffer and returns its address.
// Deduplicates identical nodes for suffix sharing.
func (b *fstSetBuilder) compileNode(node *fstBNode) uint64 {
	ckey := b.canonicalKey(node)
	if addr, ok := b.cache[ckey]; ok {
		return addr
	}

	addr := uint64(len(b.buf))
	b.writeNode(node, addr)
	b.cache[ckey] = addr
	return addr
}

// canonicalKey produces a cache key that uniquely identifies a node's content.
func (b *fstSetBuilder) canonicalKey(node *fstBNode) string {
	// 1 byte isFinal + 4 bytes numTrans + per transition: 1 byte inp + 8 bytes addr
	size := 5 + len(node.transitions)*9
	key := make([]byte, size)
	if node.isFinal {
		key[0] = 1
	}
	binary.LittleEndian.PutUint32(key[1:5], uint32(len(node.transitions)))
	for i, t := range node.transitions {
		key[5+i*9] = t.inp
		binary.LittleEndian.PutUint64(key[5+i*9+1:], t.addr)
	}
	return string(key)
}

// writeNode encodes and appends a node to the buffer.
// nodeAddr is the address where this node starts in the buffer (= len(b.buf) before write).
func (b *fstSetBuilder) writeNode(node *fstBNode, nodeAddr uint64) {
	numTrans := len(node.transitions)
	var header byte
	if node.isFinal {
		header = 0x80 | byte(numTrans&0x7F)
	} else {
		header = byte(numTrans & 0x7F)
	}
	b.buf = append(b.buf, header)

	if node.isFinal {
		b.buf = fstAppendVarint(b.buf, 0) // final output = 0 for a set
	}

	for _, t := range node.transitions {
		b.buf = append(b.buf, t.inp)
		b.buf = fstAppendVarint(b.buf, 0) // transition output = 0 for a set
		// delta = nodeAddr - childAddr (child is always earlier in the buffer)
		delta := nodeAddr - t.addr
		b.buf = fstAppendVarint(b.buf, delta)
	}
}

// finish compiles all remaining nodes and returns the complete FST bytes.
func (b *fstSetBuilder) finish() []byte {
	// Freeze everything except root
	b.freeze(1)

	// Compile root node
	root := b.stack[0]
	rootAddr := uint64(len(b.buf))
	b.writeNode(root, rootAddr)

	return fstAppendFooter(b.buf, rootAddr)
}

// fstAppendVarint appends a little-endian varint-encoded uint64.
func fstAppendVarint(buf []byte, v uint64) []byte {
	for {
		if v < 0x80 {
			return append(buf, byte(v))
		}
		buf = append(buf, byte(v&0x7F)|0x80)
		v >>= 7
	}
}

// ============================================================================
// String helpers
// ============================================================================

// strToLower converts ASCII uppercase to lowercase.
func strToLower(s string) string {
	bs := []byte(s)
	for i, c := range bs {
		if c >= 'A' && c <= 'Z' {
			bs[i] = c + 32
		}
	}
	return string(bs)
}

// strToUpper converts ASCII lowercase to uppercase.
func strToUpper(s string) string {
	bs := []byte(s)
	for i, c := range bs {
		if c >= 'a' && c <= 'z' {
			bs[i] = c - 32
		}
	}
	return string(bs)
}

// strReverse reverses a string rune by rune.
func strReverse(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}

// dedupStrings removes adjacent duplicates from a sorted slice.
func dedupStrings(ss []string) []string {
	if len(ss) == 0 {
		return ss
	}
	result := ss[:1]
	for i := 1; i < len(ss); i++ {
		if ss[i] != ss[i-1] {
			result = append(result, ss[i])
		}
	}
	return result
}
