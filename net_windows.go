package coldfire

import "strings"

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
