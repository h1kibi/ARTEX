//go:build !windows

package traffic

import "net"

// wslBridge is the non-Windows no-op counterpart of wslbridge_windows.go. A Unix
// host has no WSL guest to bridge to: the proxy's own loopback address is
// already the address every local tool reaches it on.
type wslBridge struct{}

// wslHostIPs reports no WSL NICs.
func wslHostIPs() []string { return nil }

// loopbackProxyPort pins the same addr interpretation the Windows bridge uses,
// so the rule is identical on every platform (and testable on any of them).
func loopbackProxyPort(addr string) (port string, ok bool) {
	host, p, err := net.SplitHostPort(addr)
	if err != nil || p == "" {
		return "", false
	}
	switch host {
	case "127.0.0.1", "localhost", "::1":
		return p, true
	}
	return "", false
}

// startWSLBridge never creates a listener outside Windows.
func startWSLBridge(string) *wslBridge { return nil }

func (b *wslBridge) Hosts() []string { return nil }
func (b *wslBridge) Close()          {}
