//go:build linux

package main

import (
	"os"
	"strconv"
	"strings"
)

// listenBacklogLimit is net.core.somaxconn, which caps the accept queue of every
// listener (Go asks for the maximum). 0 if it cannot be read.
func listenBacklogLimit() int {
	b, err := os.ReadFile("/proc/sys/net/core/somaxconn")
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	return n
}
