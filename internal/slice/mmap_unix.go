//go:build unix

package slice

import (
	"os"
	"syscall"
)

func platformMmap(file *os.File, size int) ([]byte, error) {
	return syscall.Mmap(int(file.Fd()), 0, size, syscall.PROT_READ, syscall.MAP_SHARED)
}

func platformMunmap(data []byte) error {
	return syscall.Munmap(data)
}
