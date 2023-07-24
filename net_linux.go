package coldfire

import (
	"strings"
	"golang.org/x/sys/unix"
)
func Networks() ([]string, error) {
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

// Hotfix much appreciated
func NetInterfaces() []string {
	return []string{"wlan0"}
}

// PortReuse sets SO_REUSEPORT on socket descriptor
// Can be used as a control parameter to a &net.ListenConfig
func PortReuse(network, address string, conn syscall.RawConn) error {
	return conn.Control(func(descriptor uintptr){
		syscall.SetsockoptInt(descriptor, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)	
	})
}