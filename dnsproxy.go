package dnsproxy

import (
	"fmt"
	"net"
	"regexp"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

type ResolvConfig struct {
	Servers []string
}

type HostItem struct {
	Pattern string
	RE      *regexp.Regexp
	IPs     []net.IP
}

func (h *HostItem) isMatch(s string) bool {
	return h.RE.MatchString(s)
}

type ProxyConfig struct {
	Hosts []*HostItem
}

var (
	udpclient = dns.Client{
		Net: "udp",
	}
	tcpclient = dns.Client{
		Net: "tcp",
	}
	resolvconf atomic.Value
	proxyconf  atomic.Value

	Debug bool

	servers struct {
		mu   sync.Mutex
		svrs []*dns.Server
	}
)

func LoadResolvConf(conf string) error {
	cfg, err := dns.ClientConfigFromFile(conf)
	if err != nil {
		return err
	}
	rc := &ResolvConfig{}
	for _, addr := range cfg.Servers {
		rc.Servers = append(rc.Servers, net.JoinHostPort(addr, cfg.Port))
	}
	SetResolvConf(rc)
	return nil
}

func SetResolvConf(rc *ResolvConfig) {
	resolvconf.Store(rc)
}

func SetProxyConf(pc *ProxyConfig) {
	proxyconf.Store(pc)
}

func unfqdn(s string) string {
	if dns.IsFqdn(s) {
		return s[:len(s)-1]
	}
	return s
}

func resolve(c *dns.Client, w dns.ResponseWriter, r *dns.Msg) {
	q := r.Question[0]
	if q.Qtype == dns.TypeA {
		pc := proxyconf.Load().(*ProxyConfig)
		for _, h := range pc.Hosts {
			if h.isMatch(unfqdn(q.Name)) {
				msg := &dns.Msg{}
				msg.SetReply(r)
				header := dns.RR_Header{
					Name:   q.Name,
					Rrtype: q.Qtype,
					Class:  q.Qclass,
					Ttl:    600,
				}
				for _, ip := range h.IPs {
					msg.Answer = append(msg.Answer, &dns.A{
						Hdr: header,
						A:   ip,
					})
				}
				w.WriteMsg(msg)

				if Debug {
					fmt.Printf("hijack dns: %s\n", q.Name)
				}
				return
			}
		}
	}

	if Debug {
		fmt.Printf("resolve dns: %s\n", q.Name)
	}

	rc := resolvconf.Load().(*ResolvConfig)
	deadline := time.Now().Add(time.Second * 2)
	for _, addr := range rc.Servers {
		msg, _, err := c.Exchange(r, addr)
		if err != nil {
			if time.Now().After(deadline) {
				dns.HandleFailed(w, r)
				return
			}
		}
		w.WriteMsg(msg)
	}
	dns.HandleFailed(w, r)
}

func resolveTCP(w dns.ResponseWriter, r *dns.Msg) {
	resolve(&tcpclient, w, r)
}

func resolveUDP(w dns.ResponseWriter, r *dns.Msg) {
	resolve(&udpclient, w, r)
}

func addServer(network string, addr string, resolver dns.HandlerFunc) *dns.Server {
	servers.mu.Lock()
	svr := &dns.Server{
		Net:     network,
		Addr:    addr,
		Handler: resolver,
	}
	servers.svrs = append(servers.svrs, svr)
	servers.mu.Unlock()
	return svr
}

func ServeTCP(network string, addr string) error {
	svr := addServer(network, addr, dns.HandlerFunc(resolveTCP))
	return svr.ListenAndServe()
}

func ServeUDP(network string, addr string) error {
	svr := addServer(network, addr, dns.HandlerFunc(resolveUDP))
	return svr.ListenAndServe()
}

func Shutdown() {
	servers.mu.Lock()
	for _, svr := range servers.svrs {
		svr.Shutdown()
	}
	servers.svrs = nil
	servers.mu.Unlock()
}

func init() {
	resolvconf.Store(&ResolvConfig{})
	proxyconf.Store(&ProxyConfig{})
}
