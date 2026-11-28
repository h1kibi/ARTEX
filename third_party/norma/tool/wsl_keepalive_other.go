//go:build !windows

package tool

import "syscall"

// hiddenWindowAttr has no meaning outside Windows; the keepalive never starts
// there, and the nil value keeps the platform-independent code compiling.
func hiddenWindowAttr() *syscall.SysProcAttr { return nil }
