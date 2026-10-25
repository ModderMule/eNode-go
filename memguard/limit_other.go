//go:build !linux && !darwin && !windows

package memguard

func cgroupMemoryLimit() int64 {
	return 0
}

// physicalMemory is unknown here: set memory.limitBytes or GOMEMLIMIT.
func physicalMemory() int64 {
	return 0
}
