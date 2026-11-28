package config

import (
	"os"
	"runtime"
	"strings"
	"unicode/utf16"
)

// WSL execution backend selection (Windows hosts).
//
// The Worker's Bash tool name promises Linux semantics, but on Windows the local
// shell is PowerShell — the single largest source of command failures in the
// historical ledgers. When a WSL distro is available the Worker is pointed at it
// instead, by injecting NORMA_WSL_DISTRO=<distro> into its BashEnv (see
// agent.bashEnv). Selection, in order:
//
//	ARTEX_WSL_DISTRO=<distro>        explicit, any distro name
//	ARTEX_WSL_DISTRO=off             explicit disable
//	config.json "wsl_distro"         explicit default
//	config.json "wsl_disabled": true disable
//	(unset)                          disabled: the host's local shell
//
// Non-Windows hosts always resolve to "" — the local shell is already bash.

// WSLDistroEnv is the environment variable both for selecting the distro
// (config-level) and for telling the tool layer which distro to run in.
const WSLDistroEnv = "ARTEX_WSL_DISTRO"

// WSLBackend returns the WSL execution setting as a value the tool layer can act
// on, distinguishing all three cases a bare distro name cannot express:
//
//	""       no WSL backend (explicitly disabled, or none installed) — the local
//	         shell is the only option
//	<distro> run commands in this distro
//
// It is exported because the PTY backend needs the same three-way answer: a caller
// that only receives "" cannot tell "nothing configured, use the machine default"
// from "the operator turned WSL off", and faking the second as the first is exactly
// how an explicit disable silently reappeared as the default distro.
func WSLBackend() (distro string, disabled bool) {
	if runtime.GOOS != "windows" {
		return "", false
	}
	if v, ok := os.LookupEnv(WSLDistroEnv); ok {
		v = strings.TrimSpace(v)
		if isDisableValue(v) {
			return "", true
		}
		if v != "" {
			return v, false
		}
	}
	cfg := Load()
	if cfg.WSLDisabled {
		return "", true
	}
	if v := strings.TrimSpace(cfg.WSLDistro); v != "" {
		if isDisableValue(v) {
			return "", true
		}
		return v, false
	}
	// Nothing configured: use the host's own Windows shell. Probing installed
	// distros and quietly starting WSL costs memory and depends on a healthy
	// wslservice; an operator who wants WSL names the distro explicitly.
	return "", true
}

func isDisableValue(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "off", "none", "disabled", "false", "0":
		return true
	}
	return false
}

// decodeWSLOutput converts wsl.exe output to UTF-8: `wsl.exe -l -q` emits
// UTF-16LE on Windows, so every other byte is a NUL.
func decodeWSLOutput(b []byte) string {
	hasNUL := false
	for _, c := range b {
		if c == 0 {
			hasNUL = true
			break
		}
	}
	if !hasNUL {
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
