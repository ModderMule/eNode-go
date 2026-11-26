//go:build unix

package main

import "syscall"

// openFileLimit is the open-file soft limit, 0 if it cannot be read.
func openFileLimit() uint64 {
	var rl syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rl); err != nil {
		return 0
	}
	return uint64(rl.Cur)
}
