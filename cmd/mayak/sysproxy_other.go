//go:build !windows

package main

import "errors"

func consoleUTF8() {}

func setSystemProxy(string) (func(), error) {
	return nil, errors.New("только для Windows")
}
