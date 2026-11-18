//go:build !windows

package main

import (
	"os"
	"syscall"
)

// relaunch — заменить процесс новой версией с теми же аргументами (тот же PID:
// systemd/procd ничего не заметят).
func relaunch(exe string) error {
	return syscall.Exec(exe, os.Args, append(os.Environ(), "MAYAK_RESTARTED=1"))
}
