package coldfire

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

func netInterfaces() []string {
	var netifaces []string

	// Enumeration phase
	ndevs, err := pcap.FindAllDevs()
	if err != nil {
		return []string{err.Error()}
	}
	for _, nd := range ndevs {
		netifaces = append(netifaces, nd.Name)
	}
	return netifaces
}
