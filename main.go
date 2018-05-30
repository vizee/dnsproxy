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
	"sync/atomic"
	"syscall"
	"time"

	"github.com/miekg/dns"
)

type resolvConfig struct {
	servers []string
}

type hostItem struct {
	pattern string
	re      *regexp.Regexp
	ips     []net.IP
}

func (h *hostItem) isMatch(s string) bool {
	return h.re.MatchString(s)
}

type proxyConfig struct {
	hosts []*hostItem
}

var (
	verbose bool

	udpclient = dns.Client{
		Net: "udp",
	}

	resolvconf atomic.Value
	proxyconf  atomic.Value
)

func logf(format string, args ...interface{}) {
	if verbose {
		log.Printf(format, args...)
	}
}

func loadResolvConf(conf string, first bool) {
	logf("loading resolv: %s", conf)
	cfg, err := dns.ClientConfigFromFile(conf)
	if err != nil {
		if first {
			log.Fatalf("load resolv: %v", err)
		} else {
			logf("load resolv: %v", err)
		}
	}
	rc := &resolvConfig{}
	for _, addr := range cfg.Servers {
		rc.servers = append(rc.servers, net.JoinHostPort(addr, cfg.Port))
	}
	resolvconf.Store(rc)
}

func parseProxyConf(conf string) (*proxyConfig, error) {
	data, err := ioutil.ReadFile(conf)
	if err != nil {
		return nil, err
	}
	pc := &proxyConfig{}
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
		for j, h := range pc.hosts {
			if h.pattern == fields[0] {
				found = j
				break
			}
		}
		if found == -1 {
			re, err := regexp.Compile(fields[0])
			if err != nil {
				return nil, fmt.Errorf("%s:%d: %v", err)
			}
			pc.hosts = append(pc.hosts, &hostItem{
				pattern: fields[0],
				re:      re,
			})
			found = len(pc.hosts) - 1
		}
		h := pc.hosts[found]
		for _, s := range fields[1:] {
			ip := net.ParseIP(s).To4()
			if len(ip) != net.IPv4len {
				return nil, fmt.Errorf("%s:%d: %s not a IPv4 address", conf, lno, s)
			}
			h.ips = append(h.ips, ip)
		}
	}
	return pc, nil
}

func loadProxyConf(conf string, first bool) {
	logf("loading config: %s", conf)
	pc, err := parseProxyConf(conf)
	if err != nil {
		if first {
			log.Fatalf("load config: %v", err)
		} else {
			logf("load config: %v", err)
		}
	}
	proxyconf.Store(pc)
}

func unfqdn(s string) string {
	if dns.IsFqdn(s) {
		return s[:len(s)-1]
	}
	return s
}

func resolve(w dns.ResponseWriter, r *dns.Msg) {
	q := r.Question[0]
	logf("resolve: %s", q.Name)
	if q.Qtype == dns.TypeA {
		pc := proxyconf.Load().(*proxyConfig)
		for _, h := range pc.hosts {
			if h.isMatch(unfqdn(q.Name)) {
				msg := &dns.Msg{}
				msg.SetReply(r)
				header := dns.RR_Header{
					Name:   q.Name,
					Rrtype: q.Qtype,
					Class:  q.Qclass,
					Ttl:    600,
				}
				for _, ip := range h.ips {
					msg.Answer = append(msg.Answer, &dns.A{
						Hdr: header,
						A:   ip,
					})
				}
				w.WriteMsg(msg)
				return
			}
		}
	}
	rc := resolvconf.Load().(*resolvConfig)
	deadline := time.Now().Add(time.Second * 2)
	for _, addr := range rc.servers {
		msg, _, err := udpclient.Exchange(r, addr)
		if err != nil {
			logf("resolve: %s by %s failed: %v", r, addr, err)
			if time.Now().After(deadline) {
				dns.HandleFailed(w, r)
				return
			}
		}
		logf("resolved: %s by %s: %s", r, addr, msg)
		w.WriteMsg(msg)
	}
	dns.HandleFailed(w, r)
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

	resolvconf.Store(&resolvConfig{})
	if resolv != "" {
		loadResolvConf(resolv, true)
	}
	proxyconf.Store(&proxyConfig{})
	if conf != "" {
		loadProxyConf(conf, true)
	}
	var servers []*dns.Server
	for _, addr := range strings.Split(listen, ";") {
		pair := strings.SplitN(addr, ":", 2)
		if len(pair) == 1 || (!strings.HasPrefix(pair[0], "udp") && !strings.HasPrefix(pair[0], "tcp")) {
			log.Fatalf("invalid address: %s", addr)
		}
		server := &dns.Server{
			Net:     pair[0],
			Addr:    pair[1],
			Handler: dns.HandlerFunc(resolve),
		}
		go func(svr *dns.Server) {
			logf("serving: %s:%s", svr.Net, svr.Addr)
			err := svr.ListenAndServe()
			if err != nil {
				log.Fatalf("server serve: %v", err)
			}
		}(server)
		servers = append(servers, server)
	}
	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGUSR1, syscall.SIGUSR2, syscall.SIGINT)
	for v := range sig {
		sn, ok := v.(syscall.Signal)
		if !ok {
			continue
		}
		if sn == syscall.SIGINT {
			logf("shutdown")
			for _, svr := range servers {
				svr.Shutdown()
			}
			break
		} else if sn == syscall.SIGUSR1 && resolv != "" {
			loadResolvConf(resolv, false)
		} else if sn == syscall.SIGUSR2 && conf != "" {
			loadProxyConf(conf, false)
		}
	}
}
