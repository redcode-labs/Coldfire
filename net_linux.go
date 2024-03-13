package coldfire

import (
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

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

func portReuse(network string, address string, conn syscall.RawConn) error {
	return conn.Control(func(descriptor uintptr) {
		syscall.SetsockoptInt(int(descriptor), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
	})
}
