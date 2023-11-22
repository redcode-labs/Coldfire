package coldfire

import (
	"bufio"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"bytes"

	//"syscall"
	"syscall"
	"time"

	portscanner "github.com/anvie/port-scanner"
	"github.com/jackpal/gateway"
	"golang.org/x/crypto/ssh"
)

// GetGlobalIp is used to return the global Ip address of the machine.
func GetGlobalIP() string {
	ip := ""
	resolvers := []string{
		"https://api.ipify.org?format=text",
		"http://myexternalip.com/raw",
		"http://ident.me",
		"https://ifconfig.me",
		"https://bot.whatismyipaddress.com/",
		"https://ifconfig.co",
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

// GetLocalIp is used to get the local Ip address of the machine.
func GetLocalIP() string {
	conn, _ := net.Dial("udp", "8.8.8.8:80")
	defer conn.Close()
	ip := conn.LocalAddr().(*net.UDPAddr).IP

	return fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])
}

// GetGatewayIP returns the Ip address of the gateway in the network where the machine resides.
func GetGatewayIP() string {
	ip, err := gateway.DiscoverGateway()
	ExitOnError(err)

	return ip.String()
}

// Returns an IP address of a given interface
func IfaceIP(ifname string) string {
	niface, err := net.InterfaceByName(ifname)
	addrs, err := niface.Addrs()
	ExitOnError(err)
	return addrs[0].(*net.IPNet).IP.String()
}

// Iface returns the currently used wireless interface and its MAC address.
func Iface() (string, string) {
	current_iface := ""
	interfaces, err := net.Interfaces()
	ExitOnError(err)

	for _, interf := range interfaces {
		if addrs, err := interf.Addrs(); err == nil {
			for _, addr := range addrs {
				if strings.Contains(addr.String(), GetLocalIP()) {
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

// PortscanSingleTimeout checks if a specific port is open in a given target.
// Connection timeout as well as no. of threads can be adjusted
func PortscanSingleTimeout(target string, port, timeout, threads int) bool {
	ps := portscanner.NewPortScanner(target, time.Duration(timeout)*time.Second, threads)
	opened_ports := ps.GetOpenedPort(port-1, port+1)
	return len(opened_ports) != 0
}

// Returns true if host is alive 
func Ping(target string) bool {
	open_counter := 0
	ports_to_check := []int{80, 443, 21, 22}
	ps := portscanner.NewPortScanner(target, 2*time.Second, 5)
	for _, port := range ports_to_check {
		if ps.IsOpen(port){
			open_counter += 1
		}
	}
	return true
}

// Removes hosts from slice that did not respond to a ping request
func RemoveInactive(targets []string) {
	for i, t := range(targets){
		if ! Ping(t){
			targets[i] = ""
		}
	}
}

// Returns a random free port 
func PortFree(port int) int {
	var a *net.TCPAddr
	a, err := net.ResolveTCPAddr("tcp", "localhost:0")
	if err != nil {
		return 0
	}
	var l *net.TCPListener
	l, _ = net.ListenTCP("tcp", a)
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func PortReuse(network string, address string, conn syscall.RawConn) error {
	return portReuse(network, address, conn)
}

// Gracefully closes an instance of net.Listener
func CloseListener(lst net.Listener){
	if lst != nil {
		lst.Close()
		lst = nil
	}
}

// Returns a slice with lines of file from URL
func Url2Lines(url string) []string {
	resp, err := http.Get(url)
	Check(err)
	defer resp.Body.Close()
	var lns []string
	scn := bufio.NewScanner(resp.Body)
	for scn.Scan() {
		lns = append(lns, scn.Text())
	}
	return lns
}

// Checks if an SSH client connection has a root context
func CheckRootSSH(client ssh.Client) bool {
	uid0_session := false
	session, err := client.NewSession()
	defer session.Close()
	Check(err)
	var user_id bytes.Buffer
	session.Stdout = &user_id
	if (session.Run("id") != nil){
		if (ContainsAny(user_id.String(), []string{"uid=0", "gid=0", "root"})){
			uid0_session = true
		}
	}
	return uid0_session
}