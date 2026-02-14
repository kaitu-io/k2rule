# P1: Windows Cross-Compilation — mmap_reader.go

## Problem

`internal/slice/mmap_reader.go` uses `syscall.Mmap`, `syscall.Munmap`, `syscall.PROT_READ`, `syscall.MAP_SHARED` which are undefined on Windows. This breaks any downstream project that cross-compiles with `GOOS=windows`.

```
$ GOOS=windows go build ./...
internal/slice/mmap_reader.go:44:23: undefined: syscall.Mmap
internal/slice/mmap_reader.go:48:11: undefined: syscall.PROT_READ
internal/slice/mmap_reader.go:49:11: undefined: syscall.MAP_SHARED
internal/slice/mmap_reader.go:100:26: undefined: syscall.Munmap
```

## Fix

Split `mmap_reader.go` into platform-specific files:

```
internal/slice/
├── mmap_reader.go          # shared MmapReader struct + methods (no syscall)
├── mmap_unix.go            # //go:build !windows — syscall.Mmap/Munmap
└── mmap_windows.go         # //go:build windows — windows.CreateFileMapping/MapViewOfFile
```

Or use `golang.org/x/exp/mmap` / `golang.org/x/sys/unix` + `golang.org/x/sys/windows` for a clean abstraction.

### Windows mmap equivalent

```go
//go:build windows

import "golang.org/x/sys/windows"

// CreateFileMapping + MapViewOfFile for read-only mmap
```

## Impact

Blocks `GOOS=windows go build` for k2 (client binary).
