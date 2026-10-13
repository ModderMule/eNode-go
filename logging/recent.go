package logging

import (
	"fmt"
	"sync"
	"time"
)

// recentCapacity is how many warnings and errors are kept for the admin surface.
const recentCapacity = 200

// Entry is one warning or error kept in memory.
type Entry struct {
	Time    time.Time
	Level   Level
	Message string
}

// recentLog is a fixed-size ring of the last warnings and errors. Info and debug
// lines are not kept: at debug level they carry peer addresses and payloads, and
// there are far too many of them to be worth a mutex each.
type recentLog struct {
	mu      sync.Mutex
	entries [recentCapacity]Entry
	next    int
	total   uint64
}

var recent recentLog

// Recent returns up to limit of the last warnings and errors, newest first, and how
// many were logged since the process started.
func Recent(limit int) (entries []Entry, total uint64) {
	return recent.snapshot(limit)
}

// String names a level the way the log lines do.
func (l Level) String() string {
	switch l {
	case LevelDebug:
		return "debug"
	case LevelWarn:
		return "warn"
	case LevelError:
		return "error"
	default:
		return "info"
	}
}

func (r *recentLog) add(level Level, format string, args []any) {
	entry := Entry{Time: time.Now(), Level: level, Message: fmt.Sprintf(format, args...)}
	r.mu.Lock()
	r.entries[r.next] = entry
	r.next = (r.next + 1) % recentCapacity
	r.total++
	r.mu.Unlock()
}

func (r *recentLog) snapshot(limit int) ([]Entry, uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	held := int(min(r.total, recentCapacity))
	if limit <= 0 || limit > held {
		limit = held
	}
	out := make([]Entry, 0, limit)
	for i := 1; i <= limit; i++ {
		out = append(out, r.entries[(r.next-i+recentCapacity)%recentCapacity])
	}
	return out, r.total
}
