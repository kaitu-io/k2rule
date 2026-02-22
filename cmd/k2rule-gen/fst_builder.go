package main

import (
	"encoding/binary"
	"sort"
)

// buildFST builds a Finite State Transducer in Rust fst crate v3 compatible format.
//
// The FST is built from a sorted list of strings (as a set, all values = 0).
// The format is compatible with the reader in internal/slice/fst.go.
//
// Format overview:
//   - Nodes are serialized bottom-up (leaf nodes first, root last)
//   - Each node: header_byte + [final_output (varint)] + [transitions...]
//   - Header byte: bit7=isFinal, bits0-6=numTransitions
//   - Each transition: input_byte + output (varint) + addr_delta (varint)
//   - addr_delta: parent_node_addr - child_node_addr
//   - Footer (last 36 bytes): version(8) + type(8) + root_addr(8) + len(8) + checksum(4)
func buildFST(sortedStrings []string) []byte {
	if len(sortedStrings) == 0 {
		return buildEmptyFST()
	}

	// Build trie from sorted strings
	root := newTrieNode()
	for _, s := range sortedStrings {
		node := root
		for i := 0; i < len(s); i++ {
			b := s[i]
			if _, ok := node.children[b]; !ok {
				node.children[b] = newTrieNode()
			}
			node = node.children[b]
		}
		node.isFinal = true
	}

	// Prepare sorted keys for all nodes (required for deterministic serialization)
	prepareSortedKeys(root)

	// Serialize nodes bottom-up (post-order traversal)
	// Each node records its own serialAddr when serialized
	var buf []byte
	serializeNode(root, &buf)

	// The root node's serialAddr is set during serializeNode
	rootAddr := uint64(root.serialAddr)

	// Build footer (36 bytes)
	// Header format (last 36 bytes of fst data):
	// [0:8]  version  = 3
	// [8:16] type     = 0 (Set)
	// [16:24] root_addr
	// [24:32] len     = number of elements
	// [32:36] checksum (unused by reader)
	footer := make([]byte, 36)
	binary.LittleEndian.PutUint64(footer[0:], 3) // version 3
	binary.LittleEndian.PutUint64(footer[8:], 0)  // type Set = 0
	binary.LittleEndian.PutUint64(footer[16:], rootAddr)
	binary.LittleEndian.PutUint64(footer[24:], uint64(len(sortedStrings)))
	binary.LittleEndian.PutUint32(footer[32:], 0) // checksum ignored

	result := make([]byte, len(buf)+len(footer))
	copy(result, buf)
	copy(result[len(buf):], footer)
	return result
}

// buildEmptyFST builds a minimal FST with no entries.
func buildEmptyFST() []byte {
	// A single non-final root node with no transitions
	// header byte = 0x00 (not final, 0 transitions)
	buf := []byte{0x00}
	rootAddr := uint64(0)

	footer := make([]byte, 36)
	binary.LittleEndian.PutUint64(footer[0:], 3) // version 3
	binary.LittleEndian.PutUint64(footer[8:], 0)  // type Set = 0
	binary.LittleEndian.PutUint64(footer[16:], rootAddr)
	binary.LittleEndian.PutUint64(footer[24:], 0) // 0 entries
	binary.LittleEndian.PutUint32(footer[32:], 0)

	result := make([]byte, len(buf)+len(footer))
	copy(result, buf)
	copy(result[len(buf):], footer)
	return result
}

// trieNode represents a node in the construction trie
type trieNode struct {
	children   map[byte]*trieNode
	isFinal    bool
	serialAddr int  // address in serialized output, set during serializeNode
	sortedKeys []byte
}

// newTrieNode creates a new trie node
func newTrieNode() *trieNode {
	return &trieNode{
		children:   make(map[byte]*trieNode),
		serialAddr: -1,
	}
}

// prepareSortedKeys sorts children keys for deterministic output
func prepareSortedKeys(node *trieNode) {
	keys := make([]byte, 0, len(node.children))
	for k := range node.children {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	node.sortedKeys = keys

	for _, child := range node.children {
		prepareSortedKeys(child)
	}
}

// serializeNode serializes a node and all its children post-order (children first).
// Sets node.serialAddr to the start position of this node in buf.
func serializeNode(node *trieNode, buf *[]byte) {
	// Serialize all children first (post-order)
	for _, k := range node.sortedKeys {
		child := node.children[k]
		if child.serialAddr == -1 {
			serializeNode(child, buf)
		}
	}

	// This node starts at the current end of buf
	node.serialAddr = len(*buf)

	// Build and append header byte
	numTrans := len(node.sortedKeys)
	header := byte(numTrans & 0x7F)
	if node.isFinal {
		header |= 0x80
	}
	*buf = append(*buf, header)

	// Write final output (value = 0 for a set)
	if node.isFinal {
		*buf = appendPackedU64(*buf, 0)
	}

	// Write transitions
	// Note: the delta is computed AFTER writing all transitions bytes, using
	// the address of THIS node (node.serialAddr) and the child's serialAddr.
	// Since transitions are inline (not separate), we can compute deltas now.
	for _, k := range node.sortedKeys {
		child := node.children[k]

		// input byte
		*buf = append(*buf, k)

		// output value (0 for sets)
		*buf = appendPackedU64(*buf, 0)

		// address delta: this_node_addr - child_node_addr
		// From reader: targetAddr = currentNodeAddr - addrDelta
		// So addrDelta = currentNodeAddr - targetAddr = node.serialAddr - child.serialAddr
		delta := uint64(node.serialAddr - child.serialAddr)
		*buf = appendPackedU64(*buf, delta)
	}
}

// appendPackedU64 appends a varint-encoded uint64 to buf.
// Uses the same encoding as the Rust fst crate (LSB first, 7 bits per byte, MSB = continue).
func appendPackedU64(buf []byte, v uint64) []byte {
	for {
		b := byte(v & 0x7F)
		v >>= 7
		if v != 0 {
			b |= 0x80
		}
		buf = append(buf, b)
		if v == 0 {
			break
		}
	}
	return buf
}

// appendSortedStrings returns a new deduplicated and sorted copy of the input slice.
func appendSortedStrings(input []string) []string {
	if len(input) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(input))
	result := make([]string, 0, len(input))
	for _, s := range input {
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			result = append(result, s)
		}
	}
	sort.Strings(result)
	return result
}
