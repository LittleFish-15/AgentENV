//go:build linux

// Print statx facts and fail closed when DAX support or its expected value is absent.
package main

import (
	"encoding/binary"
	"encoding/json"
	"os"
	"runtime"
	"syscall"
	"unsafe"
)

type result struct {
	Path           string `json:"path"`
	Errno          uint64 `json:"errno"`
	Attributes     uint64 `json:"attributes"`
	AttributesMask uint64 `json:"attributesMask"`
	DAXSupported   bool   `json:"daxSupported"`
	DAX            bool   `json:"dax"`
	ExpectedDAX    bool   `json:"expectedDax"`
	Accepted       bool   `json:"accepted"`
	Error          string `json:"error,omitempty"`
}

func main() {
	r := result{}
	if len(os.Args) != 3 || (os.Args[1] != "--expect-dax=true" && os.Args[1] != "--expect-dax=false") {
		r.Error = "usage: cache-statx --expect-dax=true|false FILE"
	} else {
		r.Path = os.Args[2]
		r.ExpectedDAX = os.Args[1] == "--expect-dax=true"
		var number uintptr
		switch runtime.GOARCH {
		case "amd64":
			number = 332
		case "arm64":
			number = 291
		default:
			r.Error = "unsupported statx architecture"
		}
		if r.Error == "" {
			path, err := syscall.BytePtrFromString(r.Path)
			if err != nil {
				r.Error = err.Error()
			} else {
				var data [256]byte
				_, _, errno := syscall.Syscall6(number, ^uintptr(99), uintptr(unsafe.Pointer(path)), 0, 0x7ff, uintptr(unsafe.Pointer(&data[0])), 0)
				r.Errno = uint64(errno)
				r.Attributes = binary.LittleEndian.Uint64(data[8:16])
				r.AttributesMask = binary.LittleEndian.Uint64(data[56:64])
				r.DAXSupported = r.AttributesMask&0x200000 != 0
				r.DAX = r.Attributes&0x200000 != 0
				r.Accepted = errno == 0 && r.DAXSupported && r.DAX == r.ExpectedDAX
			}
		}
	}
	if err := json.NewEncoder(os.Stdout).Encode(r); err != nil {
		os.Exit(2)
	}
	if !r.Accepted {
		os.Exit(1)
	}
}
