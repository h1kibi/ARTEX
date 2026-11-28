package oast

import (
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// startDNS binds the embedded DNS responder. UDP is the primary listener; the
// same port is tried for TCP, and a TCP bind failure leaves UDP serving alone.
// The HTTP listener stays optional for operators; DNS is part of the same service.
func (s *Server) startDNS() error {
	addr := strings.TrimSpace(s.opts.DNSAddr)
	switch strings.ToLower(addr) {
	case "off", "disabled", "false", "0":
		return nil
	}
	if addr == "" {
		addr = defaultDNSAddrFor(s.opts.Addr)
	}
	pc, tcpLn, host, port, err := listenDNSPair(addr)
	if err != nil {
		return err
	}
	handler := dns.HandlerFunc(s.handleDNS)
	udpSrv := &dns.Server{PacketConn: pc, Handler: handler}
	var tcpSrv *dns.Server
	if tcpLn != nil {
		tcpSrv = &dns.Server{Listener: tcpLn, Net: "tcp", Handler: handler}
	}

	s.mu.Lock()
	s.dnsConn = pc
	s.dnsTCP = tcpLn
	s.dnsSrv = udpSrv
	s.dnsTCPSrv = tcpSrv
	s.dnsAddr = net.JoinHostPort(host, port)
	s.mu.Unlock()

	go func() {
		if serveErr := udpSrv.ActivateAndServe(); serveErr != nil {
			log.Printf("[oast] DNS/UDP 监听停止: %v", serveErr)
		}
	}()
	if tcpSrv != nil {
		go func() {
			if serveErr := tcpSrv.ActivateAndServe(); serveErr != nil {
				log.Printf("[oast] DNS/TCP 监听停止: %v", serveErr)
			}
		}()
		log.Printf("[oast] DNS 带外回调监听 udp+tcp %s", net.JoinHostPort(host, port))
	} else {
		log.Printf("[oast] DNS 带外回调监听 udp %s", net.JoinHostPort(host, port))
	}
	return nil
}

// handleDNS answers one DNS query. The token is looked up among the domain's
// labels, so <token>.oast.local and any deeper payload name both resolve.
func (s *Server) handleDNS(w dns.ResponseWriter, r *dns.Msg) {
	if r == nil || len(r.Question) == 0 {
		return
	}
	q := r.Question[0]
	name := strings.TrimSuffix(q.Name, ".")
	token := s.dnsToken(name)

	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	if token != "" {
		s.publishInteraction(&Interaction{
			Token:    token,
			Protocol: "dns",
			At:       time.Now().UTC().Format(time.RFC3339),
			RemoteIP: remoteHost(w.RemoteAddr().String()),
			Method:   "DNS:" + dns.TypeToString[q.Qtype],
			Path:     name,
			Host:     name,
			TaskID:   -1,
		})
		switch q.Qtype {
		case dns.TypeA:
			if ip := net.ParseIP(preferredCallbackIPv4()); ip != nil && ip.To4() != nil {
				m.Answer = append(m.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
					A:   ip.To4(),
				})
			}
		case dns.TypeTXT:
			m.Answer = append(m.Answer, &dns.TXT{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
				Txt: []string{"oast:" + token},
			})
		}
	}
	_ = w.WriteMsg(m)
}

// dnsToken finds the identity a queried name carries: a known token label wins,
// otherwise a 32-character hex label is accepted as the token itself.
func (s *Server) dnsToken(name string) string {
	labels := strings.Split(name, ".")
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, label := range labels {
		l := strings.ToLower(label)
		if _, ok := s.tokens[l]; ok {
			return l
		}
	}
	for _, label := range labels {
		l := strings.ToLower(label)
		if isHexToken(l) {
			return l
		}
	}
	return ""
}

// isHexToken reports whether s is a 32-character lowercase hex token.
func isHexToken(s string) bool {
	if len(s) != 32 {
		return false
	}
	for i := range s {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// listenDNSPair binds UDP and (best-effort) TCP on the same port. When the
// caller asked for an ephemeral port (:0), TCP is bound FIRST: on Windows with
// Hyper-V/WSL2, dynamic UDP :0 frequently lands inside a Hyper-V excluded TCP
// port range (WSAEACCES), whereas TCP :0 skips excluded ranges and yields a
// port both protocols can share.
func listenDNSPair(addr string) (net.PacketConn, net.Listener, string, string, error) {
	_, reqPort, splitErr := net.SplitHostPort(addr)
	if splitErr == nil && (reqPort == "0" || reqPort == "") {
		for range 8 {
			ln, err := net.Listen("tcp", addr)
			if err != nil {
				break
			}
			host, port, err := net.SplitHostPort(ln.Addr().String())
			if err != nil {
				_ = ln.Close()
				return nil, nil, "", "", err
			}
			pc, uerr := net.ListenPacket("udp", net.JoinHostPort(host, port))
			if uerr == nil {
				return pc, ln, host, port, nil
			}
			_ = ln.Close()
		}
	}

	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return nil, nil, "", "", fmt.Errorf("OAST DNS UDP 监听失败: %w", err)
	}
	host, port, err := net.SplitHostPort(pc.LocalAddr().String())
	if err != nil {
		_ = pc.Close()
		return nil, nil, "", "", err
	}
	ln, lerr := net.Listen("tcp", net.JoinHostPort(host, port))
	if lerr != nil {
		log.Printf("[oast] DNS TCP 端口 %s 不可用，仅提供 UDP 服务: %v", net.JoinHostPort(host, port), lerr)
		return pc, nil, host, port, nil
	}
	return pc, ln, host, port, nil
}
