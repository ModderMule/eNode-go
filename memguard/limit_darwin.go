package memguard

import "golang.org/x/sys/unix"

func cgroupMemoryLimit() int64 {
	return 0
}

func physicalMemory() int64 {
	n, err := unix.SysctlUint64("hw.memsize")
	if err != nil {
		return 0
	}
	return int64(n)
}
