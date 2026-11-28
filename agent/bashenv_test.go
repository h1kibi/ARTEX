package agent

import (
	"runtime"
	"strings"
	"testing"

	actool "github.com/Autumn-27/norma/tool"
)

// The REAL config entry must reach the tool layer. Previously bashEnv called
// WSLDistro(), which returns "" for both "explicitly disabled" and "not
// configured"; the variable was omitted either way, and the PTY backend then fell
// back to the machine's default distro. The disable must travel as an explicit
// token.
func TestBashEnvCarriesExplicitWSLDisable(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("WSL selection is Windows-only")
	}
	t.Setenv("ARTEX_WSL_DISTRO", "off")
	env := bashEnv("", "", 0, 0)
	if !hasEnv(env, actool.WSLDistroEnv+"=off") {
		t.Fatalf("explicit disable not propagated to the tool env: %v", env)
	}
}

func TestBashEnvDefaultsToLocalOnWindowsWhenNotConfigured(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("WSL selection is Windows-only")
	}
	t.Setenv("ARTEX_WSL_DISTRO", "")
	env := bashEnv("", "", 0, 0)
	if !hasEnv(env, actool.WSLDistroEnv+"=off") {
		t.Fatalf("unconfigured WSL on Windows should default to local shell (%s=off): %v", actool.WSLDistroEnv, env)
	}
}

func TestBashEnvCarriesSelectedDistro(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("WSL selection is Windows-only")
	}
	t.Setenv("ARTEX_WSL_DISTRO", "ubuntu-22.04")
	env := bashEnv("", "", 0, 0)
	if !hasEnv(env, actool.WSLDistroEnv+"=ubuntu-22.04") {
		t.Fatalf("selected distro not propagated: %v", env)
	}
}

func hasEnv(env []string, want string) bool {
	for _, kv := range env {
		if strings.EqualFold(kv, want) {
			return true
		}
	}
	return false
}
