package coldfire

import "os/exec"

func cmdOut(command string) (string, error) {
	cmd := exec.Command("bash", "-c", command)
	output, err := cmd.CombinedOutput()
	out := string(output)
	return out, err
}
