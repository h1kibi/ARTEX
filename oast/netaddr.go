package oast

import (
	"net"
	"net/url"
	"strings"
)

// resolvePublicURL picks the callback base URL: an explicit config wins, else the
// listener address, with a reachable host substituted for a wildcard bind.
func resolvePublicURL(configured string, addr net.Addr) string {
	if v := strings.TrimSpace(configured); v != "" {
		return strings.TrimRight(v, "/")
	}
	host, port := "", "0"
	if addr != nil {
		if h, p, err := net.SplitHostPort(addr.String()); err == nil {
			host, port = h, p
		}
	}
	// Substitute a reachable host ONLY for a wildcard bind: a target on another
	// host cannot dial 0.0.0.0. A loopback bind stays loopback on purpose — the
	// caller asked for a probe the target reaches through 127.0.0.1 (same host),
	// and silently advertising the machine's LAN IP there would be unreachable.
	ip := net.ParseIP(host)
	if host == "" || ip == nil {
		host = "127.0.0.1"
	} else if ip.IsUnspecified() {
		host = preferredCallbackIPv4()
	}
	return "http://" + net.JoinHostPort(host, port)
}

// virtualInterfaceMarks name adapters that belong to a VM, container runtime,
// VPN or proxy tunnel. A callback URL built from one of them is unreachable from
// the tested network, which is exactly how 192.168.56.1 (VirtualBox host-only)
// used to be advertised.
var virtualInterfaceMarks = []string{
	"virtualbox", "vboxnet", "host-only", "vmware", "vmnet", "vethernet", "wsl",
	"hyper-v", "docker", "br-", "veth", "virbr", "podman", "tun", "tap", "utun",
	"tailscale", "zerotier", "wireguard", "clash", "mihomo", "sing-box", "npcap",
	"loopback",
}

// virtualNetworks hold address ranges proxies and link-local autoconfiguration
// hand out; neither can carry a callback from a remote target.
var virtualNetworks = parseCIDRs("198.18.0.0/15", "169.254.0.0/16")

func parseCIDRs(cidrs ...string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		if _, ipnet, err := net.ParseCIDR(c); err == nil {
			out = append(out, ipnet)
		}
	}
	return out
}

// isVirtualInterface reports whether name, MAC or ip belongs to a virtual adapter.
// The VirtualBox host-only adapter is named by the operating system's display
// language ("以太网 2" on Chinese Windows), so its locally administered 0a:00:27
// MAC identifies it where the name does not. Guest adapters use 08:00:27,
// 00:50:56 and 52:54:00 and deliberately do not match.
func isVirtualInterface(name string, mac net.HardwareAddr, ip net.IP) bool {
	n := strings.ToLower(name)
	for _, mark := range virtualInterfaceMarks {
		if strings.Contains(n, mark) {
			return true
		}
	}
	if len(mac) >= 3 && mac[0] == 0x0a && mac[1] == 0x00 && mac[2] == 0x27 {
		return true
	}
	if ip != nil {
		for _, network := range virtualNetworks {
			if network.Contains(ip) {
				return true
			}
		}
	}
	return false
}

// routeSourceIPv4 asks the kernel which local IPv4 a route to destIP would use.
// A UDP dial sends no packet; it only resolves the route and binds a local port.
func routeSourceIPv4(destIP string) string {
	conn, err := net.Dial("udp4", net.JoinHostPort(destIP, "80"))
	if err != nil {
		return ""
	}
	defer conn.Close()
	if ua, ok := conn.LocalAddr().(*net.UDPAddr); ok {
		if v4 := ua.IP.To4(); v4 != nil && !v4.IsLoopback() {
			return v4.String()
		}
	}
	return ""
}

// preferredCallbackIPv4 picks the address a target should call back on: first
// the default route's source when it sits on a physical adapter, then a physical
// adapter address, and only when this machine has none at all a virtual one.
func preferredCallbackIPv4() string {
	for _, dest := range []string{"8.8.8.8", "1.1.1.1"} {
		ip := routeSourceIPv4(dest)
		if ip == "" {
			continue
		}
		name, mac, ok := interfaceForIP(ip)
		if !ok || !isVirtualInterface(name, mac, net.ParseIP(ip)) {
			return ip
		}
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return "127.0.0.1"
	}
	physical, virtual := "", ""
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, aerr := ifc.Addrs()
		if aerr != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			v4 := ipnet.IP.To4()
			if v4 == nil || v4.IsLinkLocalUnicast() {
				continue
			}
			if isVirtualInterface(ifc.Name, ifc.HardwareAddr, v4) {
				if virtual == "" {
					virtual = v4.String()
				}
				continue
			}
			if physical == "" {
				physical = v4.String()
			}
		}
	}
	if physical != "" {
		return physical
	}
	if virtual != "" {
		return virtual
	}
	return "127.0.0.1"
}

// interfaceForIP finds the local adapter that owns ip, including its MAC.
func interfaceForIP(want string) (name string, mac net.HardwareAddr, ok bool) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", nil, false
	}
	for _, ifc := range ifaces {
		addrs, aerr := ifc.Addrs()
		if aerr != nil {
			continue
		}
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok && ipnet.IP.String() == want {
				return ifc.Name, ifc.HardwareAddr, true
			}
		}
	}
	return "", nil, false
}

// targetIPv4 extracts an IPv4 address from a target given as an IP, host:port or
// URL. Empty when the target names no address (a DNS name, or nothing).
func targetIPv4(target string) string {
	t := strings.TrimSpace(target)
	if t == "" {
		return ""
	}
	if strings.Contains(t, "://") {
		u, err := url.Parse(t)
		if err != nil {
			return ""
		}
		t = u.Hostname()
	} else if host, _, err := net.SplitHostPort(t); err == nil {
		t = host
	}
	ip := net.ParseIP(strings.Trim(t, "[]"))
	if ip == nil {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ""
}

// callbackHostForTarget chooses the local IPv4 used to reach target. A loopback
// target keeps loopback; anything else follows the route table.
func callbackHostForTarget(target string) string {
	tip := targetIPv4(target)
	if tip == "" {
		return ""
	}
	if ip := net.ParseIP(tip); ip != nil && ip.IsLoopback() {
		return "127.0.0.1"
	}
	return routeSourceIPv4(tip)
}
