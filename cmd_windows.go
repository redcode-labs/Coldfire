package coldfire

import "os/exec"

func cmdOut(command string) (string, error) {
	cmd := exec.Command("cmd", "/C", command)
	//cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	output, err := cmd.CombinedOutput()
	out := string(output)
	return out, err
}
