

<h1 align="center"> ColdFire</h1> <br>
<p align="center">
  <a>
    <img src="coldfire.png" width="450">
  </a>
</p>

<p align="center">
  Golang malware development framework
</p>

## Table of Contents
- [Table of Contents](#table-of-contents)
- [Introduction](#introduction)
- [Installation](#installation)
- [Types of functions included](#types-of-functions-included)
- [Documentation](#documentation)
  - [Logging functions](#logging-functions)
  - [Auxiliary functions](#auxiliary-functions)
  - [Reconnaissance functions](#reconnaissance-functions)
  - [Administration functions](#administration-functions)
  - [Evasion functions](#evasion-functions)
  - [Sandbox detection functions](#sandbox-detection-functions)
  - [Disruptive functions](#disruptive-functions)
- [Requirements](#requirements)
- [Disclaimer](#disclaimer)
- [License](#license)

## Introduction

ColdFire provides various methods useful for malware development in Golang.

Most functions are compatible with both Linux and Windows operating systems.

## Installation

`go get github.com/redcode-labs/Coldfire`

## Types of functions included

* Logging
* Auxiliary
* Reconnaissance
* Evasion
* Administration
* Sandbox detection
* Disruptive


## Documentation
### Logging functions

```
func F(s string, arg ...interface{}) string 
    Alias for fmt.Sprintf

func PrintGood(msg string)
    Print good status message

func PrintInfo(msg string)
    Print info status message

func PrintError(msg string)
    Print error status message
    
func PrintWarning(msg string)
    Print warning status message    
    
```
    
    
### Auxiliary functions

```
func FileToSlice(file string) []string
    Read from file and return slice with lines delimited with newline.

func Contains(s interface{}, elem interface{}) bool 
    Check if interface type contains another interface type.

func StrToInt(string_integer string) int 
    Convert string to int.

func IntToStr(i int) string 
    Converts int to string.    

func IntervalToSeconds(interval string) int 
    Converts given time interval to seconds.

func RandomInt(min int, max int) int
    Returns a random int from range.

func RandomSelectStr(list []string) string 
    Returns a random selection from slice of strings.    

func RandomSelectInt(list []int) int 
    Returns a random selection from slice of ints.    

func RandomSelectStrNested(list [][]string) []string  
    Returns a random selection from nested string slice.

func RemoveNewlines(s string) string 
    Removes "\n" and "\r" characters from string.

func FullRemove(str string, to_remove string) string 
    Removes all occurences of substring.

func RemoveDuplicatesStr(slice []string) []string 
    Removes duplicates from string slice.

func RemoveDuplicatesInt(slice []int) []int 
    Removes duplicates from int slice.

func ContainsAny(str string, elements []string) bool 
    Returns true if slice contains a string.

func RandomString(n int) string
    Generates random string of length [n]

func ExitOnError(e error)
    Handle errors

func Md5Hash(str string) string
    Returns MD5 checksum of a string

func Sha1Hash(str string) string
    Returns SHA1 checksum of a string

func MakeZip(zip_file string, files []string) error 
    Creates a zip archive from a list of files

func ReadFile(filename string) (string, error) 
    Read contents of a file.

func WriteFile(filename string) error 
    Write contents to a file.

func B64d(str string) string 
    Returns a base64 decoded string

func B64e(str string) string 
    Returns a base64 encoded string

func FileExists(file string) bool
    Check if file exists. 

func ParseCidr(cidr string) ([]string, error) 
    Returns a slice containing all possible IP addresses in the given range.

 ```

### Reconnaissance functions
```

func GetLocalIp() string
    Returns a local IP address of the machine.

func GetGlobalIp() string
    Returns a global IP address of the machine.
    
func IsRoot() bool
    Check if user has administrative privileges.
    
func Processes() (map[int]string, error)
    Returns all processes' PIDs and their corresponding names.

func Iface() string, string
    Returns name of currently used wireless interface and it's MAC address. 

func Ifaces() []string
    Returns slice containing names of all local interfaces.
    
func Disks() ([]string, error) 
    Lists local storage devices
    
func Users() []string, err
    Returns list of known users.

func Info() map[string]string 
    Returns basic system information. 
    Possible fields: username, hostname, go_os, os, 
    platform, cpu_num, kernel, core, local_ip, ap_ip, global_ip, mac.
    If the field cannot be resolved, it defaults to "N/A" value.
    
func DnsLookup(hostname string) ([]string, error) 
    Performs DNS lookup

func RdnsLookup(ip string) ([]string, error) 
    Performs reverse DNS lookup

func HostsPassive(interval string) []string, err
    Passively discovers active hosts on a network using ARP monitoring.
    Discovery time can be changed using <interval> argument.
    
func FilePermissions(filename string) (bool,bool) 
    Checks if file has read and write permissions.
    
func Portscan(target string, timeout, threads int) []int 
    Returns list of open ports on target.

func PortscanSingle(target string, port int) bool 
    Returns true if selected port is open.
    
func BannerGrab(target string, port int) (string, error) 
    Grabs a service banner string from a given port.
    
func Networks() ([]string, error) 
    Returns list of nearby wireless networks.
    
```

### Administration functions
```
func CmdOut(command string) string, error
    Execute a command and return it's output.

func CmdOutPlatform(commands map[string]string) (string, error) 
    Executes commands in platform-aware mode.
    For example, passing {"windows":"dir", "linux":"ls"} will execute different command, 
    based on platform the implant was launched on.

func CmdRun(command string)
    Unlike cmd_out(), cmd_run does not return anything, and prints output and error to STDOUT.

func CmdDir(dirs_cmd map[string]string) ([]string, error) 
    Executes commands in directory-aware mode.
    For example, passing {"/etc" : "ls"} will execute command "ls" under /etc directory.

func CmdBlind(command string)
    Run command without supervision, do not print any output.
    
func CreateUser(username, password string) error
    Creates a new user on the system.
    
func Bind(port int)
    Run a bind shell on a given port.

func Reverse(host string, port int)
    Run a reverse shell.

func SendDataTcp(host string, port int, data string) error 
    Sends string to a remote host using TCP protocol.

func SendDataUdp(host string, port int, data string) error 
    Sends string to a remote host using UDP protocol.
    
func Download(url string) error
    Downloads a file from url and save it under the same name.

func CopyFile(src string, dst string) error
    Copy a file from one place to another

func CurrentDirFiles() []string, error
    Returns list of files from current directory
```

### Evasion functions
```
func PkillPid(pid int) error
    Kill process by PID.

func PkillName(name string) errror
    Kill all processes that contain [name].

func PkillAv() err
    Kill most common AV processes.
    
func Wait(interval string)
    Does nothing for a given interval of time.

func Remove()
    Removes binary from the host.
    
func SetTtl(interval string)
    Set time-to-live of the binary.
    Should be launched as goroutine.
    
func ClearLogs() error
    Clears most system logs.
```

### Sandbox detection functions
```
func SandboxFilepath() bool 
    Detect sandbox by looking for common sandbox filepaths.
    Compatible only with windows.

func SandboxProc() bool 
    Detect sandbox by looking for common sandbox processes.

func SandboxSleep() bool
    Detect sandbox by looking for sleep-acceleration mechanism.

func SandboxDisk(size int) bool
    Detect sandbox by looking for abnormally small disk size.

func SandboxCpu(cores int) bool
    Detect sandbox by looking for abnormally small number of cpu cores.

func SandboxRam(ram_mb int) bool
    Detect sandbox by looking for abnormally small amount of RAM.

func SandboxMac() bool
    Detect sandbox by looking for sandbox-specific MAC address of the localhost. 

func SandboxUtc() bool
    Detect sandbox by looking for properly set UTC time zone. 

func SandboxProcnum(proc_num int) bool 
    Detect sandbox if small number of running processes

func SandboxTmp(entries int) bool 
    Detect sandbox if small number of entries under temporary dir

func SandboxAll() bool
    Detect sandbox using all sandbox detection methods.
    Returns true if any sandbox-detection method returns true.    

func SandboxAll_n(num int) bool
    Detect sandbox using all sandbox detection methods.
    Returns true if at least <num> detection methods return true.
```

### Disruptive functions
```
func WifiDisconnect() error 
    Disconnects from wireless access point
    
func Wipe() error
    Wipes out entire filesystem.
    
func EraseMbr(device string, partition_table bool) error 
    Erases MBR sector of a device.
    If <partition_table> is true, erases also partition table.
    
func Forkbomb()
    Runs a forkbomb.
    
func Shutdown() error
    Shutdowns the machine.

```



## Requirements
```
"github.com/google/gopacket"
"github.com/google/gopacket/layers"
"github.com/google/gopacket/pcap"
"github.com/robfig/cron"
"github.com/anvie/port-scanner"
"github.com/matishsiao/goInfo"
"github.com/fatih/color"
"github.com/minio/minio/pkg/disk"
"github.com/dustin/go-humanize"
"github.com/mitchellh/go-ps"
```

## Disclaimer
Developers are not responsible for any misuse regarding this tool.
Use it only against systems that you are permitted to attack.

## License
This software is under MIT license

