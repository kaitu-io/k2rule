//go:build !unix

package slice

import (
	"io"
	"os"
)

func platformMmap(file *os.File, size int) ([]byte, error) {
	return io.ReadAll(file)
}

func platformMunmap(data []byte) error {
	return nil
}
