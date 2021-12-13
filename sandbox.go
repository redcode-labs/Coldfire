package coldfire

import (
	"net"
	"runtime"
	"strings"
	"time"

	ps "github.com/mitchellh/go-ps"
)

// SandboxFilePath checks if the process is being run
// inside a virtualized environment.
func SandboxFilepath() bool {
	return sandboxFilepath()
}

// SandboxProc checks if there are processes that indicate
// a virtualized environment.
func SandboxProc() bool {
	sandbox_processes := []string{`vmsrvc`, `tcpview`, `wireshark`, `visual basic`, `fiddler`,
		`vmware`, `vbox`, `process explorer`, `autoit`, `vboxtray`, `vmtools`,
		`vmrawdsk`, `vmusbmouse`, `vmvss`, `vmscsi`, `vmxnet`, `vmx_svga`,
		`vmmemctl`, `df5serv`, `vboxservice`, `vmhgfs`}
	p, _ := Processes()
	for _, name := range p {
		if ContainsAny(name, sandbox_processes) {
			return true
		}
	}
	return false
}

// SandboxSleep is used to check if the virtualized environment
// is speeding up the sleeping process.
func SandboxSleep() bool {
	z := false
	firstTime := getNTPTime()
	sleepSeconds := 10
	time.Sleep(time.Duration(sleepSeconds*1000) * time.Millisecond)
	secondTime := getNTPTime()
	difference := secondTime.Sub(firstTime).Seconds()
	if difference < float64(sleepSeconds) {
		z = true
	}
	return z
}

// SandboxCpu is used to check if the environment's
// cores are less than a given integer.
func SandboxCpu(cores int) bool {
	x := false
	num_procs := runtime.NumCPU()
	if !(num_procs >= cores) {
		x = true
	}
	return x
}

// SandboxRam is used to check if the environment's
// RAM is less than a given size.
func SandboxRam(ram_mb int) bool {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	ram := m.Sys / 1024
	rmb := uint64(ram_mb)

	return ram < rmb
}

// SandboxUtc is used to check if the environment
// is in a properly set Utc timezone.
func SandboxUtc() bool {
	_, offset := time.Now().Zone()

	return offset == 0
}

// SandboxProcnum is used to check if the environment
// has processes less than a given integer.
func SandboxProcnum(proc_num int) bool {
	processes, err := ps.Processes()
	if err != nil {
		return true
	}

	return len(processes) < proc_num
}

// SandboxTmp is used to check if the environment's
// temporary directory has less files than a given integer.
func SandboxTmp(entries int) bool {
	return sandboxTmp(entries)
}

// SandboxMac is used to check if the environment's MAC address
// matches standard MAC adddresses of virtualized environments.
func SandboxMac() bool {
	hits := 0
	sandbox_macs := []string{`00:0C:29`, `00:1C:14`,
		`00:50:56`, `00:05:69`, `08:00:27`}
	ifaces, _ := net.Interfaces()

	for _, iface := range ifaces {
		for _, mac := range sandbox_macs {
			if strings.Contains(strings.ToLower(iface.HardwareAddr.String()), strings.ToLower(mac)) {
				hits += 1
			}
		}
	}

	return hits == 0
}

// SandboxAll is used to check if an environment is virtualized
// by testing all sandbox checks.
func SandboxAll() bool {
	values := []bool{
		SandboxProc(),
		SandboxFilepath(),
		SandboxCpu(2),
		SandboxSleep(),
		SandboxTmp(10),
		SandboxProcnum(100),
		SandboxRam(2048),
		SandboxUtc(),
	}

	for s := range values {
		x := values[s]
		if x {
			return true
		}
	}

	return false
}

// SandboxAlln checks if an environment is virtualized by testing all
// sandbox checks and checking if the number of successful checks is
// equal or greater to a given integer.
func SandboxAlln(num int) bool {
	num_detected := 0
	values := []bool{
		SandboxProc(),
		SandboxFilepath(),
		SandboxCpu(2),
		SandboxSleep(),
		SandboxTmp(10),
		SandboxTmp(100),
		SandboxRam(2048),
		SandboxMac(),
		SandboxUtc(),
	}
	for s := range values {
		x := values[s]
		if x {
			num_detected += 1
		}
	}

	return num_detected >= num
}
