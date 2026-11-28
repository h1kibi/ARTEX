package config

import (
	"path/filepath"
	"runtime"
	"testing"
)

// TestWSLDistroExplicitDisable: an explicit disable (env or config) wins over
// auto-detection, so an operator on Windows can keep the local shell. The result
// must report disabled=true — returning "" alone is what let the PTY backend treat
// "off" as "nothing configured" and fall back to the default distro.
func TestWSLDistroExplicitDisable(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("WSL selection is Windows-only")
	}
	t.Setenv(WSLDistroEnv, "off")
	distro, disabled := WSLBackend()
	if distro != "" || !disabled {
		t.Fatalf("WSLBackend() = (%q,%v) with %s=off, want (\"\",true)", distro, disabled, WSLDistroEnv)
	}
}

// TestWSLDistroExplicitName is honoured even when the distro is not installed:
// selection is the operator's call, and wsl.exe will report the real error.
func TestWSLDistroExplicitName(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("WSL selection is Windows-only")
	}
	t.Setenv(WSLDistroEnv, "some-custom-distro")
	distro, disabled := WSLBackend()
	if distro != "some-custom-distro" || disabled {
		t.Fatalf("WSLBackend() = (%q,%v), want (some-custom-distro,false)", distro, disabled)
	}
}

// TestWSLDistroUnsetDefaultsToLocalOnWindows: with neither the env var nor
// wsl_distro configured, Windows keeps the host's own shell instead of probing
// and starting an installed distro.
func TestWSLDistroUnsetDefaultsToLocalOnWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("WSL selection is Windows-only")
	}
	t.Setenv(WSLDistroEnv, "")
	t.Setenv("ARTEX_CONFIG", filepath.Join(t.TempDir(), "config.json"))
	distro, disabled := WSLBackend()
	if distro != "" || !disabled {
		t.Fatalf("WSLBackend() = (%q,%v) with no WSL configured on Windows, want (\"\",true)", distro, disabled)
	}
}

// TestWSLDistroNonWindows: the local shell on Unix is already bash.
func TestWSLDistroNonWindows(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("non-Windows only")
	}
	t.Setenv(WSLDistroEnv, "kali-linux")
	if distro, disabled := WSLBackend(); distro != "" || disabled {
		t.Fatalf("WSLBackend() = (%q,%v) on %s, want (\"\",false)", distro, disabled, runtime.GOOS)
	}
}

func TestDecodeWSLOutput(t *testing.T) {
	// "kali-linux\r\n" as UTF-16LE, which is what `wsl.exe -l -q` emits.
	raw := []byte{'k', 0, 'a', 0, 'l', 0, 'i', 0, '-', 0, 'l', 0, 'i', 0, 'n', 0, 'u', 0, 'x', 0}
	if got := decodeWSLOutput(raw); got != "kali-linux" {
		t.Fatalf("decodeWSLOutput = %q", got)
	}
	if got := decodeWSLOutput([]byte("plain")); got != "plain" {
		t.Fatalf("decodeWSLOutput(plain) = %q", got)
	}
}

func TestIsDisableValue(t *testing.T) {
	for _, v := range []string{"off", "OFF", " none ", "disabled", "false", "0"} {
		if !isDisableValue(v) {
			t.Errorf("isDisableValue(%q) = false", v)
		}
	}
	for _, v := range []string{"kali-linux", "default", ""} {
		if isDisableValue(v) {
			t.Errorf("isDisableValue(%q) = true", v)
		}
	}
}
