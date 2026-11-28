// Package config loads runtime configuration from a JSON file, with environment
// variables taking precedence. Currently it carries the PostgreSQL connection.
package config

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Database is the PostgreSQL connection config. Either set DSN directly, or set
// the component fields and a DSN is assembled from them.
type Database struct {
	DSN      string `json:"dsn"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	User     string `json:"user"`
	Password string `json:"password"`
	DBName   string `json:"dbname"`
	SSLMode  string `json:"sslmode"`
}

// Config is the on-disk config file shape.
type Config struct {
	Database Database `json:"database"`
	SkillDir string   `json:"skill_dir"`
	// WSLDistro / WSLDisabled select the Windows WSL execution backend for the
	// agent runtime (see WSLDistro). WSL runs only when a distro name is set here
	// or through ARTEX_WSL_DISTRO; with neither set the host uses its local shell.
	// Both fields are ignored on non-Windows hosts, where the local shell is
	// already bash.
	WSLDistro   string `json:"wsl_distro"`
	WSLDisabled bool   `json:"wsl_disabled"`
	// OAST configures the built-in out-of-band callback service.
	OAST OAST `json:"oast"`
	// Traffic configures the recording/interception proxy's TLS policy.
	Traffic Traffic `json:"traffic"`
}

// Traffic carries the interception proxy's settings that are NOT the capture
// toggle (that lives in the database so the UI can flip it at runtime).
type Traffic struct {
	// VerifyUpstream makes the proxy verify target certificates. Off by default: the
	// proxy exists to intercept authorized pentest targets, which are routinely
	// self-signed. It now sits in front of every request (capture on or off) because
	// the egress scope gate lives on it, so this choice is stated here explicitly
	// instead of being implied by the MITM's own defaults.
	VerifyUpstream bool `json:"verify_upstream"`
}

// OAST is the built-in out-of-band application security testing listener.
// No field is required: with no configuration the service binds ephemeral ports
// on all interfaces and advertises the route-selected IPv4, so a target inside
// the tested network can always reach it. Set Addr to "127.0.0.1:0" when the
// target reaches the callback through a tunnel instead. Set Addr to pin the
// listener (e.g. "10.0.0.7:8081") and PublicURL when the reachable address
// differs from the bound one (NAT, a jump host, a reverse tunnel).
//
// DNSAddr carries the DNS listener separately ("off"/"disabled" turns it off);
// InteractshURL delegates callbacks to an external service instead of the
// embedded listeners, with InteractshToken as its optional auth token.
type OAST struct {
	Disabled        bool   `json:"disabled"`
	Addr            string `json:"addr"`
	PublicURL       string `json:"public_url"`
	DNSAddr         string `json:"dns_addr"`
	InteractshURL   string `json:"interactsh_url"`
	InteractshToken string `json:"interactsh_token"`
}

// OASTSettings is the fully resolved OAST configuration the server consumes.
type OASTSettings struct {
	Addr            string
	PublicURL       string
	DNSAddr         string
	InteractshURL   string
	InteractshToken string
	Enabled         bool
}

// BaseDir is the directory that anchors all runtime artifacts (config.json and
// the data/ store). It is the directory the running binary lives in, so a
// distributed executable keeps its files next to itself on any OS (Windows,
// Linux, …) regardless of the working directory it is launched from.
//
// When launched via `go run`, the binary is throwaway: it sits either in a temp
// build dir (cache miss → fresh link) OR straight inside the Go build cache
// (cache hit → run from $GOCACHE/.../...-d). We detect both and fall back to the
// current working directory so dev artifacts (data/, transcripts) and config
// resolve against the project dir, not the throwaway binary's location.
func BaseDir() string {
	exe, err := os.Executable()
	if err != nil {
		return "."
	}
	dir := filepath.Dir(exe)
	if isGoRunDir(dir) {
		return "." // throwaway `go run` binary → use CWD
	}
	return dir
}

// isGoRunDir reports whether dir is where `go run` parked its executable: under
// the system temp dir (cache miss), or anywhere inside a Go build cache
// (…/go-build/…, the cache-hit case — NOT under os.TempDir(), which is why the
// old temp-only check failed intermittently). In both cases the binary is
// throwaway, so config/data must resolve against the CWD.
func isGoRunDir(dir string) bool {
	if tmp := os.TempDir(); tmp != "" {
		if rel, err := filepath.Rel(tmp, dir); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return true
		}
	}
	for _, seg := range strings.Split(filepath.ToSlash(dir), "/") {
		if seg == "go-build" {
			return true
		}
	}
	return false
}

// Path returns the config file path. Resolution order:
//  1. env ARTEX_CONFIG (explicit override)
//  2. ./config.json in the current working directory (running from the project
//     dir — robust no matter where `go run` placed the temp/cached binary)
//  3. config.json next to the executable (a distributed binary keeps it beside)
//
// The first existing file wins. If none exist, the CWD path is returned so the
// "not found" message points at the project dir the user most likely expected.
func Path() string {
	if v := strings.TrimSpace(os.Getenv("ARTEX_CONFIG")); v != "" {
		return v
	}
	var candidates []string
	if cwd, err := os.Getwd(); err == nil {
		candidates = append(candidates, filepath.Join(cwd, "config.json"))
	}
	candidates = append(candidates, filepath.Join(BaseDir(), "config.json"))
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return candidates[0]
}

// Load reads and parses the config file. A missing/unreadable file yields a zero
// Config (so callers fall back to defaults) rather than an error.
func Load() Config {
	var c Config
	b, err := os.ReadFile(Path())
	if err != nil {
		return c
	}
	_ = json.Unmarshal(b, &c)
	return c
}

// SkillDir returns the skill root directory with precedence:
//
//	env ARTEX_SKILL_DIR  >  config file (skill_dir)  >  BaseDir()/skills
//
// The directory is created if it does not exist.
func SkillDir() string {
	var d string
	if v := strings.TrimSpace(os.Getenv("ARTEX_SKILL_DIR")); v != "" {
		d = v
	} else if v := strings.TrimSpace(Load().SkillDir); v != "" {
		d = v
	} else {
		d = filepath.Join(BaseDir(), "skills")
	}
	_ = os.MkdirAll(d, 0o755)
	return d
}

// PostgresDSN resolves the connection string with precedence:
//
//	env ARTEX_PG_DSN  >  config file (database.dsn, or assembled from fields)
//
// There is NO built-in fallback: when neither source supplies a database config,
// it returns an error naming the config path it inspected, so startup fails loudly
// instead of silently connecting to a wrong default. source describes where the
// DSN came from (for startup logging).
func PostgresDSN() (dsn, source string, err error) {
	if v := strings.TrimSpace(os.Getenv("ARTEX_PG_DSN")); v != "" {
		return v, "环境变量 ARTEX_PG_DSN", nil
	}
	db := Load().Database
	if d := strings.TrimSpace(db.DSN); d != "" {
		return d, "配置文件 " + Path() + " (database.dsn)", nil
	}
	if db.Host != "" || db.DBName != "" || db.User != "" {
		return db.buildDSN(), "配置文件 " + Path() + " (database 字段)", nil
	}
	return "", "", fmt.Errorf("未找到数据库配置：环境变量 ARTEX_PG_DSN 未设置，且配置文件 %s 未提供 database（dsn 或 host/user/dbname）。请创建该配置文件或设置环境变量后重试", Path())
}

// OASTListen resolves the OAST listener with precedence:
//
//	env ARTEX_OAST_ADDR  >  config file (oast.addr)  >  "" (all interfaces, ephemeral port)
//
// env ARTEX_OAST_DISABLED=1 (or config oast.disabled) turns the service off.
func OASTListen() (addr, publicURL string, enabled bool) {
	c := OASTConfig()
	return c.Addr, c.PublicURL, c.Enabled
}

// OASTConfig resolves the complete OAST configuration, applying the environment
// overrides on top of the config file.
func OASTConfig() OASTSettings {
	c := Load()
	enabled := !c.OAST.Disabled
	if v := strings.TrimSpace(os.Getenv("ARTEX_OAST_DISABLED")); v != "" {
		enabled = v != "1" && !strings.EqualFold(v, "true")
	}
	out := OASTSettings{
		Addr:            strings.TrimSpace(c.OAST.Addr),
		PublicURL:       strings.TrimSpace(c.OAST.PublicURL),
		DNSAddr:         strings.TrimSpace(c.OAST.DNSAddr),
		InteractshURL:   strings.TrimSpace(c.OAST.InteractshURL),
		InteractshToken: strings.TrimSpace(c.OAST.InteractshToken),
		Enabled:         enabled,
	}
	if v := strings.TrimSpace(os.Getenv("ARTEX_OAST_ADDR")); v != "" {
		out.Addr = v
	}
	if v := strings.TrimSpace(os.Getenv("ARTEX_OAST_PUBLIC_URL")); v != "" {
		out.PublicURL = v
	}
	if v := strings.TrimSpace(os.Getenv("ARTEX_OAST_DNS_ADDR")); v != "" {
		out.DNSAddr = v
	}
	if v := strings.TrimSpace(os.Getenv("ARTEX_OAST_INTERACTSH_URL")); v != "" {
		out.InteractshURL = v
	}
	if v := strings.TrimSpace(os.Getenv("ARTEX_OAST_INTERACTSH_TOKEN")); v != "" {
		out.InteractshToken = v
	}
	return out
}

func (d Database) buildDSN() string {
	host := d.Host
	if host == "" {
		host = "127.0.0.1"
	}
	port := d.Port
	if port == 0 {
		port = 5432
	}
	ssl := d.SSLMode
	if ssl == "" {
		ssl = "disable"
	}
	u := url.URL{
		Scheme: "postgres",
		Host:   host + ":" + strconv.Itoa(port),
		Path:   "/" + d.DBName,
	}
	if d.User != "" {
		if d.Password != "" {
			u.User = url.UserPassword(d.User, d.Password)
		} else {
			u.User = url.User(d.User)
		}
	}
	u.RawQuery = url.Values{"sslmode": {ssl}}.Encode()
	return u.String()
}

// String is a redacted view of the resolved DSN (password masked) for logging.
func Redact(dsn string) string {
	u, err := url.Parse(dsn)
	if err != nil {
		return dsn
	}
	if u.User != nil {
		if _, hasPw := u.User.Password(); hasPw {
			u.User = url.UserPassword(u.User.Username(), "****")
		}
	}
	return fmt.Sprintf("%s", u.String())
}
