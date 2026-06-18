package main

import (
	"bufio"
	"net"
	"os"
	"os/exec"
	"strings"
)

// icmpAlive returns true if the host answers a single ICMP echo within ~1s.
// Uses the system `ping` to avoid requiring raw-socket privileges.
func icmpAlive(ip string) bool {
	cmd := exec.Command("ping", "-c", "1", "-W", "1", ip)
	return cmd.Run() == nil
}

// arpKnown reports whether the given IP has a resolved (non-zero) entry in the
// kernel ARP table (/proc/net/arp). Best-effort; returns false on non-Linux.
func arpKnown(ip string) bool {
	f, err := os.Open("/proc/net/arp")
	if err != nil {
		return false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Scan() // skip header
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 4 {
			continue
		}
		if fields[0] == ip {
			mac := fields[3]
			if mac != "" && mac != "00:00:00:00:00:00" {
				return true
			}
		}
	}
	return false
}

// localIPv4s returns this host's non-loopback IPv4 addresses.
func localIPv4s() ([]string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []string
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() {
				continue
			}
			if v4 := ip.To4(); v4 != nil {
				out = append(out, v4.String())
			}
		}
	}
	return out, nil
}
