package slice

import (
	"encoding/binary"
	"fmt"
)

// FSTReader is a lightweight FST (Finite State Transducer) reader
// compatible with Rust's fst crate binary format
type FSTReader struct {
	data []byte
}

// FST format constants
const (
	// Version 3 of the fst crate format
	fstVersion = 3
)

// NewFSTReader creates a new FST reader from bytes
func NewFSTReader(data []byte) (*FSTReader, error) {
	if len(data) < 36 {
		return nil, fmt.Errorf("FST data too small: %d bytes", len(data))
	}

	// The FST format has a header at the end (last 36 bytes)
	// Format (from end):
	// - 8 bytes: version (u64 LE)
	// - 8 bytes: type (u64 LE)
	// - 8 bytes: root addr (u64 LE)
	// - 8 bytes: len (u64 LE)
	// - 4 bytes: checksum (u32 LE)

	// Validate version (we support version 3)
	versionOffset := len(data) - 36
	version := binary.LittleEndian.Uint64(data[versionOffset : versionOffset+8])
	if version != fstVersion {
		return nil, fmt.Errorf("unsupported FST version: %d (expected %d)", version, fstVersion)
	}

	return &FSTReader{
		data: data,
	}, nil
}

// Contains checks if the FST contains the exact key
func (f *FSTReader) Contains(key []byte) bool {
	_, found := f.get(key)
	return found
}

// HasPrefix checks if the FST has any key with the given prefix
func (f *FSTReader) HasPrefix(prefix []byte) bool {
	// For our use case (domain matching), we just need Contains
	// HasPrefix would require more complex FST traversal
	return f.Contains(prefix)
}

// get looks up a key in the FST
// Returns (value, found)
func (f *FSTReader) get(key []byte) (uint64, bool) {
	if len(f.data) < 36 {
		return 0, false
	}

	// Get root address from header (last 36 bytes)
	rootAddrOffset := len(f.data) - 20
	rootAddr := binary.LittleEndian.Uint64(f.data[rootAddrOffset : rootAddrOffset+8])

	// Start from root node
	addr := rootAddr
	var output uint64 = 0

	// Follow transitions for each byte in the key
	for _, b := range key {
		node, err := f.readNode(addr)
		if err != nil {
			return 0, false
		}

		// Find transition for this byte
		trans, found := node.findTransition(b)
		if !found {
			return 0, false
		}

		// Accumulate output
		output += trans.out

		// Move to next node
		addr = trans.addr
	}

	// Check if we're at a final state
	node, err := f.readNode(addr)
	if err != nil {
		return 0, false
	}

	if !node.isFinal {
		return 0, false
	}

	// Add final output
	output += node.finalOutput

	return output, true
}

// fstNode represents a node in the FST
type fstNode struct {
	isFinal     bool
	finalOutput uint64
	transitions []fstTransition
}

// fstTransition represents a transition in the FST
type fstTransition struct {
	inp  byte   // input byte
	out  uint64 // output value
	addr uint64 // target address
}

// findTransition finds a transition for the given input byte
func (n *fstNode) findTransition(b byte) (fstTransition, bool) {
	for _, trans := range n.transitions {
		if trans.inp == b {
			return trans, true
		}
	}
	return fstTransition{}, false
}

// readNode reads a node at the given address
func (f *FSTReader) readNode(addr uint64) (*fstNode, error) {
	if addr >= uint64(len(f.data)) {
		return nil, fmt.Errorf("invalid node address: %d", addr)
	}

	pos := int(addr)
	if pos >= len(f.data) {
		return nil, fmt.Errorf("address out of bounds: %d", pos)
	}

	// Read node header byte
	header := f.data[pos]
	pos++

	node := &fstNode{}

	// Parse node type and flags from header
	// Bit 0-6: number of transitions
	// Bit 7: is final
	numTrans := int(header & 0x7F)
	node.isFinal = (header & 0x80) != 0

	// Read final output if this is a final state
	if node.isFinal {
		val, n := f.readPackedU64(pos)
		node.finalOutput = val
		pos += n
	}

	// Read transitions
	node.transitions = make([]fstTransition, numTrans)
	for i := 0; i < numTrans; i++ {
		if pos >= len(f.data) {
			return nil, fmt.Errorf("unexpected end of data reading transition %d", i)
		}

		// Read input byte
		inp := f.data[pos]
		pos++

		// Read output value
		out, n := f.readPackedU64(pos)
		pos += n

		// Read target address (delta encoded)
		addrDelta, n := f.readPackedU64(pos)
		pos += n

		// Calculate absolute address (addresses are stored as deltas from current position)
		targetAddr := addr - addrDelta

		node.transitions[i] = fstTransition{
			inp:  inp,
			out:  out,
			addr: targetAddr,
		}
	}

	return node, nil
}

// readPackedU64 reads a packed u64 value (varint encoding)
// Returns (value, bytes_read)
func (f *FSTReader) readPackedU64(pos int) (uint64, int) {
	var val uint64
	var shift uint
	bytesRead := 0

	for {
		if pos+bytesRead >= len(f.data) {
			return val, bytesRead
		}

		b := f.data[pos+bytesRead]
		bytesRead++

		val |= uint64(b&0x7F) << shift
		if (b & 0x80) == 0 {
			break
		}
		shift += 7
	}

	return val, bytesRead
}
