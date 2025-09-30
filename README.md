# ARP spoof

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-yellow.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Go Reference](https://pkg.go.dev/badge/github.com/shadowy-pycoder/arpspoof.svg)](https://pkg.go.dev/github.com/shadowy-pycoder/arpspoof)
![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/shadowy-pycoder/arpspoof)
[![Go Report Card](https://goreportcard.com/badge/github.com/shadowy-pycoder/arpspoof)](https://goreportcard.com/report/github.com/shadowy-pycoder/arpspoof)
![GitHub Release](https://img.shields.io/github/v/release/shadowy-pycoder/arpspoof)
![GitHub Downloads (all assets, all releases)](https://img.shields.io/github/downloads/shadowy-pycoder/arpspoof/total)
![GitHub Downloads (all assets, latest release)](https://img.shields.io/github/downloads/shadowy-pycoder/arpspoof/latest/total)

## Install

```shell
CGO_ENABLED=0 go install -ldflags "-s -w" -trimpath github.com/shadowy-pycoder/arpspoof/cmd/af@latest
```

## Usage

```shell
af -h
Usage of af:
  -I    Display list of interfaces and exit.
  -d    Enable debug logging
  -f    Run ARP spoofing in fullduplex mode
  -g string
        IPv4 address of custom gateway (Default: default gateway)
  -i string
        The name of the network interface. Example: eth0 (Default: default interface)
  -nocolor
        Disable colored output
  -t string
        Targets for ARP spoofing. Example: "targets 10.0.0.1,10.0.0.5-10,192.168.1.*,192.168.10.0/24" (Default: entire subnet)
```

### Usage as a library

See [https://github.com/shadowy-pycoder/go-http-proxy-to-socks](https://github.com/shadowy-pycoder/go-http-proxy-to-socks)
