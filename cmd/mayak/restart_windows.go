//go:build windows

package main

import (
	"os"
	"os/exec"
)

// relaunch — запустить новую версию в том же окне консоли и выйти.
func relaunch(exe string) error {
	c := exec.Command(exe, os.Args[1:]...)
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	c.Env = append(os.Environ(), "MAYAK_RESTARTED=1")
	if err := c.Start(); err != nil {
		return err
	}
	os.Exit(0)
	return nil
}
