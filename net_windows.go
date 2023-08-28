package coldfire

import (
	"strings"
	"golang.org/x/sys/windows"
	"syscall"
)

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

// PortReuse sets SO_REUSEPORT on socket descriptor
// Can be used as a control parameter to a &net.ListenConfig
func portReuse(network string, address string, conn syscall.RawConn) error {
	return conn.Control(func(descriptor uintptr){
		windows.SetsockoptInt(windows.Handle(descriptor), windows.SOL_SOCKET, windows.SO_REUSEADDR, 1)	
	})
}