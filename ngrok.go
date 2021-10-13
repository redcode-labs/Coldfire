package coldfire

import (
	"io/ioutil"
	"net/http"

	"github.com/savaki/jq"
)

// StartNgrokTCP exposes a TCP server on a given port.
func StartNgrokTCP(port int) error {
	_, err := CmdOut(F("ngrok tcp %d", port))

	return err
}

// StartNgrokHTTP exposes a web server on a given port.
func StartNgrokHTTP(port int) error {
	_, err := CmdOut(F("ngrok http %d", port))

	return err
}

// GetNgrokURL returns the URL of the Ngrok tunnel exposing the machine.
func GetNgrokURL() (string, error) {
	local_url := "http://localhost:4040/api/tunnels"
	resp, err := http.Get(local_url)

	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	json, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	jq_op_1, _ := jq.Parse(".tunnels")
	json_1, _ := jq_op_1.Apply(json)
	jq_op_2, _ := jq.Parse(".[0]")
	json_2, _ := jq_op_2.Apply(json_1)
	jq_op_3, _ := jq.Parse(".public_url")
	json_3, _ := jq_op_3.Apply(json_2)
	json_sanitized := FullRemove(string(json_3), `"`)

	return json_sanitized, nil
}
