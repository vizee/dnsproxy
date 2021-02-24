package main

import (
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"

	"github.com/vizee/dnsproxy"
)

var (
	verbose bool
)

func loadResolvConf(conf string, first bool) {
	log.Printf("loading resolv: %s", conf)
	err := dnsproxy.LoadResolvConf(conf)
	if err != nil {
		if first {
			log.Fatalf("load resolv: %v", err)
		} else {
			log.Printf("load resolv: %v", err)
		}
	}
}

func parseProxyConf(conf string) (*dnsproxy.ProxyConfig, error) {
	data, err := ioutil.ReadFile(conf)
	if err != nil {
		return nil, err
	}
	pc := &dnsproxy.ProxyConfig{}
	lns := bytes.Split(data, []byte{'\n'})
	for i, ln := range lns {
		lno := i + 1
		ln = bytes.TrimSpace(ln)
		if len(ln) == 0 || ln[0] == '#' {
			continue
		}
		if p := bytes.IndexByte(ln, '#'); p >= 0 {
			ln = ln[:p]
		}
		fields := strings.Fields(string(ln))
		if len(fields) < 2 {
			return nil, fmt.Errorf("%s:%d: fields not enought", conf, lno)
		}
		found := -1
		for j, h := range pc.Hosts {
			if h.Pattern == fields[0] {
				found = j
				break
			}
		}
		if found == -1 {
			re, err := regexp.Compile(fields[0])
			if err != nil {
				return nil, fmt.Errorf("%s:%d: %v", err)
			}
			pc.Hosts = append(pc.Hosts, &dnsproxy.HostItem{
				Pattern: fields[0],
				RE:      re,
			})
			found = len(pc.Hosts) - 1
		}
		h := pc.Hosts[found]
		for _, s := range fields[1:] {
			ip := net.ParseIP(s).To4()
			if len(ip) != net.IPv4len {
				return nil, fmt.Errorf("%s:%d: %s not a IPv4 address", conf, lno, s)
			}
			h.IPs = append(h.IPs, ip)
		}
	}
	return pc, nil
}

func loadProxyConf(conf string, first bool) {
	log.Printf("loading config: %s", conf)
	pc, err := parseProxyConf(conf)
	if err != nil {
		if first {
			log.Fatalf("load config: %v", err)
		} else {
			log.Printf("load config: %v", err)
		}
	}
	dnsproxy.SetProxyConf(pc)
}

func main() {
	log.SetPrefix("")
	log.SetOutput(os.Stderr)
	var (
		listen string
		conf   string
		resolv string
	)
	flag.StringVar(&listen, "l", "udp::53", "")
	flag.StringVar(&conf, "c", "dnsproxy.conf", "dnsproxy.conf")
	flag.StringVar(&resolv, "r", "/etc/resolv.conf", "resolv.conf")
	flag.BoolVar(&verbose, "V", false, "verbose")
	flag.Parse()

	dnsproxy.Debug = verbose

	if resolv != "" {
		loadResolvConf(resolv, true)
	}
	if conf != "" {
		loadProxyConf(conf, true)
	}
	for _, addr := range strings.Split(listen, ";") {
		pair := strings.SplitN(addr, ":", 2)
		if len(pair) == 1 {
			log.Fatalf("invalid address: %s", addr)
		}
		switch {
		case strings.HasPrefix(pair[0], "udp"):
			go dnsproxy.ServeUDP(pair[0], pair[1])
		case strings.HasPrefix(pair[0], "tcp"):
			go dnsproxy.ServeTCP(pair[0], pair[1])
		default:
			log.Fatalf("unsupported network: %s", pair[0])
		}
	}
	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGUSR1, syscall.SIGUSR2, syscall.SIGINT)
	for v := range sig {
		sn, ok := v.(syscall.Signal)
		if !ok {
			continue
		}
		if sn == syscall.SIGINT {
			log.Printf("shutdown")
			dnsproxy.Shutdown()
			break
		} else if sn == syscall.SIGUSR1 && resolv != "" {
			loadResolvConf(resolv, false)
		} else if sn == syscall.SIGUSR2 && conf != "" {
			loadProxyConf(conf, false)
		}
	}
}
