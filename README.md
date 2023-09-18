

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

## Types of functions included (for maldev)

* Logging
* Auxiliary
* Reconnaissance
* Evasion
* Administration
* Sandbox detection
* Disruptive
* Low-evel

## Types of functions included (for infra)

* Network manipulations
* Cryptography
* IO with specialized readers
* Tunneling
* Target processing


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

