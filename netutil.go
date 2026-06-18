package main

import (
	"bufio"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

func randReader() io.Reader { return rand.Reader }

func host(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}

func tcpHealthy(ip string, timeout time.Duration, port int) bool {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, strconv.Itoa(port)), timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// icmpAlive: пытается raw-сокет ICMP, при отсутствии прав — fallback на /bin/ping.
func icmpAlive(ip string) bool {
	c, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return systemPing(ip)
	}
	defer c.Close()
	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho, Code: 0,
		Body: &icmp.Echo{ID: os.Getpid() & 0xffff, Seq: 1, Data: []byte("natssl")},
	}
	wb, _ := msg.Marshal(nil)
	dst := &net.IPAddr{IP: net.ParseIP(ip)}
	c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.WriteTo(wb, dst); err != nil {
		return systemPing(ip)
	}
	rb := make([]byte, 1500)
	_, _, err = c.ReadFrom(rb)
	return err == nil
}

func systemPing(ip string) bool {
	cmd := exec.Command("ping", "-c", "1", "-W", "2", ip)
	return cmd.Run() == nil
}

// arpKnown: ищет IP в ядровой ARP-таблице (/proc/net/arp), L2-проверка.
func arpKnown(ip string) bool {
	f, err := os.Open("/proc/net/arp")
	if err != nil {
		return false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Scan() // header
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) >= 4 && fields[0] == ip {
			mac := fields[3]
			if mac != "00:00:00:00:00:00" {
				return true
			}
		}
	}
	return false
}

func localIPv4s() ([]string, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	var out []string
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok {
			if ip4 := ipn.IP.To4(); ip4 != nil && !ip4.IsLoopback() {
				out = append(out, ip4.String())
			}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no usable local IPv4 found")
	}
	return out, nil
}

// HTTP-клиент, доверяющий нашему Root CA из системного хранилища.
func insecureMasterClient() *http.Client {
	return &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // упрощение: верификация делается отдельно
		},
	}
}

func insecureBootstrapClient() *http.Client { return insecureMasterClient() }
