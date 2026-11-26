//go:build !unix

package main

// openFileLimit is 0: this platform has no open-file rlimit.
func openFileLimit() uint64 { return 0 }
