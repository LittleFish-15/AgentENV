//go:build linux

// Check the actual file after lower/overlay mounting, not just device capability.
package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"unsafe"
)

func check(name string) error {
	var number uintptr
	switch runtime.GOARCH {
	case "amd64":
		number = 332
	case "arm64":
		number = 291
	default:
		return fmt.Errorf("unsupported statx architecture")
	}
	path, err := syscall.BytePtrFromString(name)
	if err != nil {
		return err
	}
	// Linux statx: attributes at byte 8, attributes_mask at byte 56.
	var data [256]byte
	_, _, errno := syscall.Syscall6(number, ^uintptr(99), uintptr(unsafe.Pointer(path)),
		0, 0x7ff, uintptr(unsafe.Pointer(&data[0])), 0)
	const dax = uint64(0x200000)
	attributes := binary.LittleEndian.Uint64(data[8:16])
	mask := binary.LittleEndian.Uint64(data[56:64])
	if errno != 0 || mask&dax == 0 || attributes&dax == 0 {
		return fmt.Errorf("DAX is not active for %s (errno=%d mask=%x attributes=%x)",
			name, errno, mask, attributes)
	}
	return nil
}

func main() {
	var err error
	if len(os.Args) == 3 && os.Args[1] == "--tree" {
		count := 0
		err = filepath.WalkDir(os.Args[2], func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			count++
			if count > 100000 {
				return fmt.Errorf("DAX metadata scan exceeds 100000 entries")
			}
			if !entry.Type().IsRegular() {
				return nil
			}
			info, infoErr := entry.Info()
			if infoErr != nil {
				return infoErr
			}
			if info.Size() == 0 {
				return nil
			}
			return check(path)
		})
	} else if len(os.Args) == 2 {
		err = check(os.Args[1])
	} else {
		err = fmt.Errorf("usage: dax-check FILE | dax-check --tree DIRECTORY")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("DAX_ACTIVE %s\n", os.Args[len(os.Args)-1])
}
