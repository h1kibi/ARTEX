//go:build windows

package traffic

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestWSLBridgeEndToEnd is the real-machine regression for the "WSL2 cannot reach
// the loopback proxy" outage: the proxy binds 127.0.0.1, the bridge publishes the
// same port on the WSL virtual NIC only, and a command executed inside the real
// `wsl.exe` guest must reach a target through it — recorded, attributed, and
// without leaking the internal Proxy-Authorization to the target.
func TestWSLBridgeEndToEnd(t *testing.T) {
	ips := wslHostIPs()
	if len(ips) == 0 {
		t.Skip("no WSL virtual NIC on this machine")
	}
	if _, err := exec.LookPath("wsl.exe"); err != nil {
		t.Skip("wsl.exe unavailable")
	}

	// Target the proxy dials from the Windows side, so a loopback address is fine.
	var gotAuth string
	var hit bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
		gotAuth = r.Header.Get("Proxy-Authorization")
		_, _ = io.WriteString(w, "from-target")
	}))
	defer target.Close()

	addr := freeLoopbackAddr(t)
	tr, err := Open(t.TempDir(), addr)
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()
	go func() { _ = tr.Start() }()
	waitListening(t, addr)

	// Start() also brought up the bridge; it must be on the WSL NIC, never 0.0.0.0.
	hosts := tr.wsl.Hosts()
	if len(hosts) == 0 {
		t.Skip("WSL bridge did not come up (port already in use on the WSL NIC?)")
	}
	for _, h := range hosts {
		host, _, _ := net.SplitHostPort(h)
		if host == "0.0.0.0" || host == "" || host == "::" {
			t.Fatalf("bridge must not bind a wildcard address: %s", h)
		}
		if net.ParseIP(host) == nil || net.ParseIP(host).IsLoopback() {
			t.Fatalf("bridge bound to a non-WSL address: %s", h)
		}
	}

	proxyURL := "http://artex:t77_i5@" + hosts[0]
	// --noproxy '' is required: the guest's default NO_PROXY covers 127.0.0.1,
	// which is exactly the target address, so curl would bypass the proxy and try
	// the guest's own loopback instead (the very failure this bridge fixes).
	script := `curl -s -m 20 --noproxy '' --proxy ` + proxyURL + ` ` + target.URL + `/wsl-probe?a=1`
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "wsl.exe", "-e", "bash", "-lc", script).CombinedOutput()
	if err != nil {
		t.Fatalf("wsl curl failed: %v\noutput: %s", err, out)
	}
	if !strings.Contains(string(out), "from-target") {
		t.Fatalf("target not reached from WSL: %q", out)
	}
	if !hit {
		t.Fatal("target was never hit")
	}
	if gotAuth != "" {
		t.Fatalf("internal tag leaked to the target: %q", gotAuth)
	}

	// The exchange is recorded with the tag carried across the WSL hop.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		rows, err := tr.query(queryFilter{Host: "127.0.0.1", TaskID: 77}, 0, 10)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) > 0 {
			if rows[0].IntentID != 5 {
				t.Fatalf("intent_id = %d, want 5", rows[0].IntentID)
			}
			if !strings.Contains(rows[0].URL, "/wsl-probe") {
				t.Fatalf("wrong exchange recorded: %s", rows[0].URL)
			}
			req, _, err := tr.Get(rows[0].ID)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(req, "artex:t77") {
				t.Fatalf("recorded request leaks the internal credential:\n%s", req)
			}
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	// Surface the recorded rows to make a failure diagnosable.
	dump, _ := json.Marshal(tr.mustAllRows())
	t.Fatalf("WSL traffic was not recorded with its tag; rows=%s", dump)
}

// TestWSLBridgeOnlyForLoopbackProxy: a proxy already bound to every interface
// needs no bridge, and the bridge must not add a second listener for it.
func TestWSLBridgeOnlyForLoopbackProxy(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:8788", ":8788", "192.168.1.5:8788"} {
		if b := startWSLBridge(addr); b != nil {
			b.Close()
			t.Fatalf("startWSLBridge(%q) must be a no-op", addr)
		}
	}
	if _, ok := loopbackProxyPort("127.0.0.1:8788"); !ok {
		t.Fatal("127.0.0.1 must be recognized as loopback")
	}
	if _, ok := loopbackProxyPort(":8788"); ok {
		t.Fatal("a bare :port binds all interfaces and must not be bridged")
	}
}

// TestWSLHostIPsAreWSLNICs: every address the bridge would bind belongs to an
// interface named after WSL, so a LAN NIC can never be exposed.
func TestWSLHostIPsAreWSLNICs(t *testing.T) {
	ips := wslHostIPs()
	ifaces, _ := net.Interfaces()
	byIP := map[string]string{}
	for _, in := range ifaces {
		addrs, _ := in.Addrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok {
				byIP[ipn.IP.String()] = in.Name
			}
		}
	}
	for _, ip := range ips {
		name := byIP[ip]
		if !strings.Contains(strings.ToUpper(name), "WSL") {
			t.Fatalf("bridge address %s belongs to non-WSL interface %q", ip, name)
		}
	}
}

// TestWSLBridgeForwardsBidirectionally proves the relay carries both directions
// (a plain echo round-trip on a raw socket through the bridge).
func TestWSLBridgeForwardsBidirectionally(t *testing.T) {
	ips := wslHostIPs()
	if len(ips) == 0 {
		t.Skip("no WSL virtual NIC")
	}
	// Stand in for the proxy: a raw echo listener on loopback.
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()

	b := startWSLBridge(echo.Addr().String())
	if b == nil {
		t.Skip("bridge unavailable (port in use on the WSL NIC)")
	}
	defer b.Close()
	hosts := b.Hosts()
	if len(hosts) == 0 {
		t.Fatal("bridge has no listeners")
	}

	conn, err := net.DialTimeout("tcp", hosts[0], 5*time.Second)
	if err != nil {
		t.Fatalf("dial bridge %s: %v", hosts[0], err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte("ping-through-bridge")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read back through bridge: %v", err)
	}
	if string(buf[:n]) != "ping-through-bridge" {
		t.Fatalf("bridge mangled the stream: %q", buf[:n])
	}
}

// mustAllRows is a test-only dump of the index for failure diagnostics.
func (t *Traffic) mustAllRows() []ExchangeMeta {
	rows, err := t.Search("", 0, 50)
	if err != nil {
		return nil
	}
	return rows
}
