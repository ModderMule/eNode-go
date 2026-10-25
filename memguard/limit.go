package memguard

import (
	"os"
	"strconv"
	"strings"
)

// noCgroupLimit is the threshold above which a cgroup v1 limit means "unlimited":
// v1 reports a page-rounded MaxInt64 instead of "max".
const noCgroupLimit = 1 << 62

// cgroupFiles are read in order: cgroup v2, then v1.
var cgroupFiles = []string{
	"/sys/fs/cgroup/memory.max",
	"/sys/fs/cgroup/memory/memory.limit_in_bytes",
}

// ParseCgroupLimit reads a cgroup memory limit file's content: bytes, or 0 for
// "max", an unlimited v1 value, or anything unreadable.
func ParseCgroupLimit(content string) int64 {
	s := strings.TrimSpace(content)
	if s == "" || s == "max" {
		return 0
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n <= 0 || n >= noCgroupLimit {
		return 0
	}
	return n
}

// readCgroupLimit is the first cgroup limit found among files, 0 when none is set.
func readCgroupLimit(files []string) int64 {
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		if n := ParseCgroupLimit(string(b)); n > 0 {
			return n
		}
	}
	return 0
}
