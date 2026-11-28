//go:build windows

package tool

import "syscall"

// hiddenWindowAttr starts the background keepalive without a console window.
func hiddenWindowAttr() *syscall.SysProcAttr {
	const createNoWindow = 0x08000000
	return &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
}
