//go:build windows

package traffic

import (
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

// WSL bridge: make a loopback-only recording proxy reachable from a WSL2 guest.
//
// The proxy binds 127.0.0.1:<port> on purpose (no LAN exposure). A WSL2 guest
// cannot reach the host's loopback — its own 127.0.0.1 is the guest — and the
// only host address it can route to is the NAT gateway, which is the IP of the
// WSL virtual NIC (e.g. vEthernet (WSL) → 172.20.16.1). Nothing listens on that
// address, so every WSL-side HTTP tool used to die with "connection refused".
//
// The bridge listens on exactly those WSL NIC addresses (never 0.0.0.0, never a
// physical NIC) and forwards to the proxy's loopback listener.

// wslBridge is the set of listeners forwarding WSL-side connections to the
// proxy's loopback address. Nil-safe: a nil bridge does nothing.
type wslBridge struct {
	target string // 127.0.0.1:<port>
	lns    []net.Listener
	mu     sync.Mutex
	closed bool
	wg     sync.WaitGroup
}

// wslHostIPs returns the IPv4 addresses of this machine's WSL virtual NICs.
// Interface-name matching is the discriminator: WSL creates a vEthernet adapter
// whose name contains "WSL", and binding to anything else would expose the
// proxy on a real network.
func wslHostIPs() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []string
	for _, in := range ifaces {
		if in.Flags&net.FlagUp == 0 || in.Flags&net.FlagLoopback != 0 {
			continue
		}
		if !strings.Contains(strings.ToUpper(in.Name), "WSL") {
			continue
		}
		addrs, err := in.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ip, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			v4 := ip.IP.To4()
			if v4 == nil || v4.IsLoopback() || v4.IsLinkLocalUnicast() {
				continue
			}
			out = append(out, v4.String())
		}
	}
	return out
}

// loopbackProxyPort reports the port of a loopback-only proxy address and
// whether addr is loopback at all. A proxy bound to any other address is already
// reachable from WSL and needs no bridge.
func loopbackProxyPort(addr string) (port string, ok bool) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || port == "" {
		return "", false
	}
	switch host {
	case "127.0.0.1", "localhost", "::1", "0.0.0.0", "":
		// "" and 0.0.0.0 bind every interface already — nothing to bridge, and
		// binding a second listener would only add a duplicate.
		return port, host == "127.0.0.1" || host == "localhost" || host == "::1"
	}
	return "", false
}

// startWSLBridge opens the WSL-side listeners for a loopback-bound proxy.
// Returns nil when the proxy is not loopback-only or no WSL NIC exists.
func startWSLBridge(proxyAddr string) *wslBridge {
	port, ok := loopbackProxyPort(proxyAddr)
	if !ok {
		return nil
	}
	ips := wslHostIPs()
	if len(ips) == 0 {
		return nil
	}
	b := &wslBridge{target: net.JoinHostPort("127.0.0.1", port)}
	for _, ip := range ips {
		ln, err := net.Listen("tcp", net.JoinHostPort(ip, port))
		if err != nil {
			log.Printf("[traffic] WSL 桥接 %s:%s 监听失败（该地址可能已被占用）: %v", ip, port, err)
			continue
		}
		b.lns = append(b.lns, ln)
		log.Printf("[traffic] WSL 桥接已启用：%s:%s → %s（仅 WSL 虚拟网卡，未暴露局域网）", ip, port, b.target)
	}
	if len(b.lns) == 0 {
		return nil
	}
	b.wg.Add(len(b.lns))
	for _, ln := range b.lns {
		go b.serve(ln)
	}
	return b
}

// Hosts lists the addresses the bridge accepts connections on.
func (b *wslBridge) Hosts() []string {
	if b == nil {
		return nil
	}
	out := make([]string, 0, len(b.lns))
	for _, ln := range b.lns {
		out = append(out, ln.Addr().String())
	}
	return out
}

func (b *wslBridge) serve(ln net.Listener) {
	defer b.wg.Done()
	for {
		conn, err := ln.Accept()
		if err != nil {
			return // listener closed
		}
		b.wg.Add(1)
		go func() {
			defer b.wg.Done()
			b.forward(conn)
		}()
	}
}

// forward relays one accepted connection to the loopback proxy and back.
func (b *wslBridge) forward(client net.Conn) {
	defer client.Close()
	upstream, err := net.DialTimeout("tcp", b.target, 5*time.Second)
	if err != nil {
		log.Printf("[traffic] WSL 桥接转发到 %s 失败: %v", b.target, err)
		return
	}
	defer upstream.Close()
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(upstream, client); done <- struct{}{} }()
	go func() { _, _ = io.Copy(client, upstream); done <- struct{}{} }()
	<-done // either direction ending is the end of this exchange
}

// Close stops every listener and waits for in-flight forwards.
func (b *wslBridge) Close() {
	if b == nil {
		return
	}
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return
	}
	b.closed = true
	lns := b.lns
	b.lns = nil
	b.mu.Unlock()
	for _, ln := range lns {
		_ = ln.Close()
	}
	b.wg.Wait()
}
