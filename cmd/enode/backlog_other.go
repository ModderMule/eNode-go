//go:build !linux

package main

// listenBacklogLimit is 0 outside Linux, where it is not read.
func listenBacklogLimit() int { return 0 }
