package memguard

import "golang.org/x/sys/unix"

func cgroupMemoryLimit() int64 {
	return readCgroupLimit(cgroupFiles)
}

func physicalMemory() int64 {
	var info unix.Sysinfo_t
	if err := unix.Sysinfo(&info); err != nil {
		return 0
	}
	return int64(uint64(info.Totalram) * uint64(info.Unit))
}
