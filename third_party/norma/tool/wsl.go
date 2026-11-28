package tool

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/url"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"
	"unicode/utf16"
)

// WSL execution backend (Windows hosts only).
//
// On Windows the local shell is PowerShell, which breaks the overwhelmingly
// common Linux command shapes an authorised pentest run emits — `curl -s -m 5`,
// `2>/dev/null`, `<<'EOF'` heredocs, single-quote nesting — and offers no PTY at
// all. When a WSL distro (e.g. kali-linux) is available the host injects
// NORMA_WSL_DISTRO=<distro> into ToolContext.Env; tools then run the command
// through `wsl.exe -d <distro> -e env … bash -lc <command>` instead.
//
// The env var is authoritative: without it every command keeps the legacy
// local-shell path, so unit tests and hosts that never opt in are unaffected.

// WSLDistroEnv names the distro a bash/shell command must run in. Set by the
// host (Worker BashEnv) on Windows only; ignored on other platforms.
const WSLDistroEnv = "NORMA_WSL_DISTRO"

// wslPassEnv is the set of variables carried from the Windows-side tool env into
// the WSL command: the egress proxy (so target traffic still flows through the
// recording MITM) and the CA variables each toolchain reads. Values that are
// Windows paths are converted with toWSLPath first.
var wslPassEnv = []string{
	"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
	"http_proxy", "https_proxy", "all_proxy", "no_proxy",
	"NODE_USE_ENV_PROXY",
	"SSL_CERT_FILE", "CURL_CA_BUNDLE", "REQUESTS_CA_BUNDLE", "GIT_SSL_CAINFO", "NODE_EXTRA_CA_CERTS",
}

// wslPathVars are the variables whose value is a filesystem path, so a drive
// path (C:\...) must be rewritten to its /mnt/c/... form before WSL sees it —
// otherwise every toolchain fails to open the CA bundle.
var wslPathVars = map[string]bool{
	"SSL_CERT_FILE": true, "CURL_CA_BUNDLE": true, "REQUESTS_CA_BUNDLE": true,
	"GIT_SSL_CAINFO": true, "NODE_EXTRA_CA_CERTS": true,
}

// wslDistroFromEnv returns the distro named by env (last entry wins, matching
// exec's own semantics), or "" when the command must run on the local shell.
func wslDistroFromEnv(env []string) string {
	distro := ""
	for _, kv := range env {
		if k, v, ok := strings.Cut(kv, "="); ok && k == WSLDistroEnv {
			distro = strings.TrimSpace(v)
		}
	}
	switch strings.ToLower(distro) {
	case "", "off", "none", "disabled", "false", "0":
		return ""
	}
	return distro
}

// wslDistroDisabledInEnv reports whether env EXPLICITLY turns the WSL backend off
// (NORMA_WSL_DISTRO=off/none/disabled/false/0). It differs from "no entry at
// all": with no entry the caller may still choose the machine's default distro,
// but an explicit disable must never fall back — otherwise an operator who turned
// WSL off still gets WSL-backed commands and PTYs.
func wslDistroDisabledInEnv(env []string) bool {
	set, value := false, ""
	for _, kv := range env {
		if k, v, ok := strings.Cut(kv, "="); ok && k == WSLDistroEnv {
			set, value = true, strings.TrimSpace(v)
		}
	}
	if !set {
		return false
	}
	switch strings.ToLower(value) {
	case "off", "none", "disabled", "false", "0":
		return true
	}
	return false
}

// ToWSLPath converts a Windows drive path to the standard WSL mount form
// (C:\workspace\a b → /mnt/c/workspace/a b). POSIX paths and relative paths are
// returned unchanged.
func ToWSLPath(p string) string {
	return toWSLPath(p)
}

// ToWSLPathForDistro converts p using the mount root probed from distro, so a
// distro with automount root "/" maps C: to /c instead of /mnt/c. An empty
// distro name selects the /mnt default.
func ToWSLPathForDistro(distro, p string) string {
	return toWSLPathWithRoot(p, wslGuestInfoFor(distro).mountRoot)
}

// toWSLPath maps a Windows absolute path to the standard WSL mount path
// (C:\workspace\a b → /mnt/c/workspace/a b). Anything already POSIX is returned
// unchanged, as is a relative path (its meaning is the WSL cwd, not the host's).
func toWSLPath(p string) string {
	return toWSLPathWithRoot(p, "/mnt")
}

// toWSLPathWithRoot maps a drive path under the distro's actual mount root. A
// distro configured with automount root "/" exposes C: at /c, while the default
// layout puts it at /mnt/c.
func toWSLPathWithRoot(p, mountRoot string) string {
	s := strings.TrimSpace(p)
	if s == "" {
		return ""
	}
	if strings.HasPrefix(s, "/") {
		return s
	}
	if mountRoot == "" {
		mountRoot = "/mnt"
	}
	s = strings.ReplaceAll(s, "\\", "/")
	if len(s) >= 2 && s[1] == ':' && isASCIILetter(s[0]) {
		drive := strings.ToLower(string(s[0]))
		rest := strings.TrimPrefix(s[2:], "/")
		base := strings.TrimRight(mountRoot, "/")
		if base == "" {
			base = "/"
		}
		switch {
		case rest == "" && base == "/":
			return "/" + drive
		case rest == "":
			return base + "/" + drive
		case base == "/":
			return "/" + drive + "/" + rest
		default:
			return base + "/" + drive + "/" + rest
		}
	}
	return s
}

func isASCIILetter(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

// wslEnvArgs returns the "KEY=VALUE" pairs handed to `env` inside WSL, in the
// order: non-interactive defaults, then the passthrough whitelist from env.
// Loopback proxy addresses are rewritten to the WSL2 host gateway because a WSL2
// guest's 127.0.0.1 is its own loopback — the recording proxy lives on the
// Windows side and is only reachable at the NAT gateway address.
func wslEnvArgs(env []string, info wslGuestInfo) []string {
	out := make([]string, 0, len(nonInteractiveEnv)+len(wslPassEnv))
	size := map[string]int{}
	for _, kv := range nonInteractiveEnv {
		if k := envKey(kv); k != "" {
			size[k] = len(out)
		}
		out = append(out, kv)
	}
	// Later entries win, like withEnv: rebuild a key→value view first.
	values := map[string]string{}
	order := make([]string, 0, len(env))
	for _, kv := range env {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || k == WSLDistroEnv || !wslVarAllowed(k) {
			continue
		}
		if _, dup := values[k]; !dup {
			order = append(order, k)
		}
		values[k] = v
	}
	for _, k := range order {
		v := values[k]
		if wslPathVars[k] {
			v = toWSLPathWithRoot(v, info.mountRoot)
		}
		if isProxyVar(k) {
			rewritten, ok := wslProxyValueForGuest(v, info)
			if !ok {
				// Unreachable from the guest: injecting it would make every HTTP
				// tool fail with "connection refused", so the variable is left out
				// entirely (no proxy hint) instead of being poisoned.
				continue
			}
			v = rewritten
		}
		if i, isDefault := size[k]; isDefault {
			out[i] = k + "=" + v // host override replaces the default
			continue
		}
		out = append(out, k+"="+v)
	}
	return out
}

func wslVarAllowed(k string) bool {
	for _, n := range wslPassEnv {
		if n == k {
			return true
		}
	}
	return false
}

func isProxyVar(k string) bool {
	switch strings.ToLower(k) {
	case "http_proxy", "https_proxy", "all_proxy":
		return true
	}
	return false
}

// wslProxyValue prepares one proxy variable for the guest, borrowing only the
// host gateway address.
func wslProxyValue(raw, hostAddr string) (string, bool) {
	return wslProxyValueForGuest(raw, wslGuestInfo{gateway: hostAddr})
}

// wslProxyValueForGuest prepares one proxy variable for the guest. A loopback
// proxy (127.0.0.1 / localhost / ::1) lives on the Windows side. With mirrored
// networking the guest shares the host loopback, so the address passes through
// unchanged. Under NAT that address is the guest's own loopback, so it must be
// rewritten to the host gateway and only if something is really listening there.
// ok=false means "do not export this variable".
//
// A non-loopback proxy (an upstream egress proxy on the LAN) is passed through
// unchanged: it is reachable from the guest as-is.
func wslProxyValueForGuest(raw string, info wslGuestInfo) (string, bool) {
	if raw == "" {
		return "", false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return raw, true
	}
	switch u.Hostname() {
	case "127.0.0.1", "localhost", "::1":
	default:
		return raw, true // routable from the guest already
	}
	port := u.Port()
	if port == "" {
		return "", false
	}
	if info.mirrored && hostReachable("127.0.0.1", port) {
		return raw, true
	}
	if info.gateway == "" || !hostReachable(info.gateway, port) {
		return "", false
	}
	u.Host = net.JoinHostPort(info.gateway, port)
	return u.String(), true
}

// hostReachable reports whether hostAddr:port accepts a TCP connection from this
// machine — i.e. whether the traffic bridge (or anything else) actually listens
// on the WSL-facing address. Results are cached briefly: the probe runs once per
// Bash call, and a negative answer must not cost 150ms on every command.
func hostReachable(hostAddr, port string) bool {
	key := hostAddr + ":" + port
	if v, ok := proxyProbeCache.Load(key); ok {
		if e := v.(proxyProbe); time.Since(e.at) < e.ttl {
			return e.ok
		}
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(hostAddr, port), 150*time.Millisecond)
	ok := err == nil
	if ok {
		_ = conn.Close()
	}
	// A negative answer is cached briefly: the traffic proxy + bridge start in a
	// goroutine, so the first command of a run can probe before the listener is
	// up. A long negative TTL would then drop the proxy for that whole window.
	ttl := proxyProbeTTL
	if !ok {
		ttl = proxyProbeNegTTL
	}
	proxyProbeCache.Store(key, proxyProbe{ok: ok, at: time.Now(), ttl: ttl})
	return ok
}

type proxyProbe struct {
	ok  bool
	at  time.Time
	ttl time.Duration
}

const (
	proxyProbeTTL    = 30 * time.Second
	proxyProbeNegTTL = 2 * time.Second
)

var proxyProbeCache sync.Map

// --- distro discovery ---

type wslProbe struct {
	once    sync.Once
	distros []string
	err     error
}

var wslProbeOnce wslProbe

// wslInternalDistro reports whether name belongs to a container runtime's
// hidden Linux VM rather than a user-facing distribution. Docker Desktop and
// friends expose these through `wsl -l`; treating one as "the" distro breaks
// path mounts and leaves the user without a usable shell.
func wslInternalDistro(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	switch n {
	case "docker-desktop", "docker-desktop-data", "rancher-desktop-data", "podman-machine-default":
		return true
	}
	return strings.HasPrefix(n, "docker-desktop")
}

// wslListDistros returns the installed WSL distributions, first-listed (the
// machine default) first, with container runtime internals removed. Cached for
// the process: the list changes only when an operator installs a distro, which
// is not a per-command event.
func wslListDistros() ([]string, error) {
	if runtime.GOOS != "windows" {
		return nil, nil
	}
	wslProbeOnce.once.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, "wsl.exe", "-l", "-q").Output()
		if err != nil {
			wslProbeOnce.err = err
			return
		}
		for _, line := range strings.Split(decodeWSLText(out), "\n") {
			name := strings.TrimSpace(strings.ReplaceAll(line, "\x00", ""))
			if name == "" || wslInternalDistro(name) {
				continue
			}
			wslProbeOnce.distros = append(wslProbeOnce.distros, name)
		}
	})
	return wslProbeOnce.distros, wslProbeOnce.err
}

// defaultWSLDistro returns the machine's default user distro, or "" when WSL is
// absent. Used when a PTY is requested without naming a distro.
func defaultWSLDistro() string {
	ds, err := wslListDistros()
	if err != nil || len(ds) == 0 {
		return ""
	}
	return ds[0]
}

// wslGuestInfo is what the guest side of one distro looks like. The three
// answers come from a single probe because each one costs a wsl.exe start.
type wslGuestInfo struct {
	mountRoot string // parent of the drive mounts: "/mnt" by default, "/" for automount root "/"
	gateway   string // host address under NAT networking
	mirrored  bool   // wslinfo reports "mirrored" networking
}

type guestInfoCache struct {
	once sync.Once
	info wslGuestInfo
}

var wslGuestInfos sync.Map // distro → *guestInfoCache

// wslGuestInfoFor returns the cached facts about distro, probing once.
func wslGuestInfoFor(distro string) wslGuestInfo {
	if distro == "" {
		return wslGuestInfo{mountRoot: "/mnt"}
	}
	v, _ := wslGuestInfos.LoadOrStore(distro, &guestInfoCache{})
	c := v.(*guestInfoCache)
	c.once.Do(func() {
		c.info = probeWSLGuest(distro)
	})
	return c.info
}

// wslGuestProbeScript prints the mount root, the networking mode and the default
// gateway in one guest start.
const wslGuestProbeScript = `p=""
while read -r dev mnt fst rest; do
  case "$fst" in
    drvfs|9p)
      case "$mnt" in
        /*/[A-Za-z]|/[A-Za-z]) p="${mnt%/*}"; [ -z "$p" ] && p="/"; break;;
      esac;;
  esac
done < /proc/mounts
echo "MOUNT:$p"
echo "MIRROR:$(wslinfo --networking-mode 2>/dev/null)"
echo "GW:$(ip route show default 2>/dev/null | awk '{print $3; exit}')"`

func probeWSLGuest(distro string) wslGuestInfo {
	info := wslGuestInfo{mountRoot: "/mnt"}
	if runtime.GOOS != "windows" {
		return info
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "wsl.exe", "-d", distro, "-e", "sh", "-c", wslGuestProbeScript).Output()
	if err != nil {
		return info
	}
	return parseWSLGuestProbe(out)
}

// parseWSLGuestProbe decodes the probe script output. A missing or empty MOUNT
// line keeps the /mnt default so a partially failed probe still yields usable
// paths.
func parseWSLGuestProbe(raw []byte) wslGuestInfo {
	info := wslGuestInfo{mountRoot: "/mnt"}
	for _, line := range strings.Split(decodeWSLText(raw), "\n") {
		line = strings.TrimSpace(strings.ReplaceAll(line, "\x00", ""))
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch key {
		case "MOUNT":
			if value != "" && strings.HasPrefix(value, "/") {
				info.mountRoot = value
			}
		case "MIRROR":
			info.mirrored = strings.Contains(strings.ToLower(value), "mirrored")
		case "GW":
			info.gateway = value
		}
	}
	return info
}

// shellProcess builds the child process for command, selecting the WSL backend
// when the tool env names a distro on Windows. The bool reports whether the
// command runs inside WSL (its stderr carries wsl.exe's own NAT chatter, which
// the caller filters out with wslNoiseFilter).
func shellProcess(ctx context.Context, command, workDir string, env []string) (*exec.Cmd, bool) {
	if runtime.GOOS == "windows" {
		if distro := wslDistroFromEnv(env); distro != "" {
			return wslBashCmd(ctx, distro, command, workDir, env), true
		}
	}
	shell, flags := shellCmd()
	cmd := exec.CommandContext(ctx, shell, append(flags, wrapLocalShellCommand(command))...)
	cmd.Dir = workDir
	cmd.Env = withEnv(env)
	return cmd, false
}

// wslBashCmd builds `wsl.exe -d <distro> --cd <path> -e env … bash -lc <cmd>`.
// -lc (not -c) so the distro's login profile is applied — that is what puts
// /usr/local/bin, ~/.local/bin and the kali toolchain on PATH.
func wslBashCmd(ctx context.Context, distro, command, workDir string, env []string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, "wsl.exe", wslExecArgs(distro, command, workDir, env)...)
	// Never set Dir to the Windows path: wsl.exe would reject it. The Linux cwd
	// comes from --cd above.
	cmd.Env = withEnv(env)
	ensureWSLKeepalive(distro)
	return cmd
}

// wslExecArgs assembles the wsl.exe arguments shared by the bash backend and the
// ConPTY session.
func wslExecArgs(distro, command, workDir string, env []string) []string {
	info := wslGuestInfoFor(distro)
	args := []string{"-d", distro}
	if dir := wslWorkDir(workDir, info.mountRoot); dir != "" {
		args = append(args, "--cd", dir)
	}
	args = append(args, "-e", "env")
	args = append(args, wslEnvArgs(env, info)...)
	args = append(args, "bash", "-lc", command)
	return args
}

// wslNoiseLine matches wsl.exe's own diagnostics, which it prints to stderr in
// UTF-16 regardless of the command: most commonly the mirrored-localhost/NAT
// proxy warning. Leaving them in the merged stdout+stderr makes a successful
// command look like it printed garbage.
var wslNoiseLine = regexp.MustCompile(`(?i)^\s*wsl:\s`)

// wslNoiseFilter is an io.Writer that decodes wsl.exe's UTF-16 stderr lines,
// drops its diagnostics, and forwards everything else as UTF-8 to the wrapped
// writer. One filter serves a command's stdout and stderr (that is how Bash
// merges them), so it serialises its own writes.
type wslNoiseFilter struct {
	mu  sync.Mutex
	w   io.Writer
	buf []byte
	err error
}

func newWSLNoiseFilter(w io.Writer) *wslNoiseFilter { return &wslNoiseFilter{w: w} }

func (f *wslNoiseFilter) Write(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.buf = append(f.buf, p...)
	f.flush(false)
	if f.err != nil {
		return 0, f.err
	}
	return len(p), nil
}

// Close flushes a trailing partial line; the result is idempotent.
func (f *wslNoiseFilter) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.flush(true)
	return f.err
}

func (f *wslNoiseFilter) flush(final bool) {
	for {
		i := bytes.IndexByte(f.buf, '\n')
		if i < 0 {
			break
		}
		line := decodeWSLText(f.buf[:i])
		f.buf = f.buf[i+1:]
		f.skipNULTerminator()
		f.emit(line)
	}
	if final && len(f.buf) > 0 {
		line := decodeWSLText(f.buf)
		f.buf = nil
		f.emit(line)
	}
}

// skipNULTerminator eats the high byte of a UTF-16LE "\n" (0a 00) that the split
// above leaves at the head of the next line. Without it the following (UTF-8)
// line would still contain a NUL and be misread as UTF-16.
func (f *wslNoiseFilter) skipNULTerminator() {
	for len(f.buf) > 0 && f.buf[0] == 0 {
		f.buf = f.buf[1:]
	}
}

func (f *wslNoiseFilter) emit(line string) {
	if f.err != nil {
		return
	}
	line = strings.TrimRight(line, "\x00\r")
	if wslNoiseLine.MatchString(line) {
		return // wsl.exe's own diagnostic, not command output
	}
	_, f.err = io.WriteString(f.w, line+"\n")
}

// decodeWSLText turns one buffered line into UTF-8. wsl.exe writes its stderr
// as UTF-16LE, so a line carrying NUL bytes is decoded as such; command output
// (UTF-8, no NULs above the first byte) passes through untouched.
func decodeWSLText(b []byte) string {
	if bytes.IndexByte(b, 0) < 0 {
		return string(b)
	}
	if len(b)%2 == 1 {
		b = b[:len(b)-1]
	}
	u := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		u = append(u, uint16(b[i])|uint16(b[i+1])<<8)
	}
	return string(utf16.Decode(u))
}
