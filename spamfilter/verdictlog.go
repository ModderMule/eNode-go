package spamfilter

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"enode/logging"
)

// maxVerdictLogBytes is the size at which the verdict log is moved aside to
// "<file>.1", replacing the previous one, so the log holds between one and two times
// this much.
const maxVerdictLogBytes = 64 << 20

// LogEntry is one line of the verdict log, a JSON object. Type says which fields are
// set: "file" for a scored file, "publisher" for a flagged session, and "decision" for
// what the operator did with a file.
type LogEntry struct {
	Time string `json:"time"`
	Type string `json:"type"`

	Hash    string         `json:"hash,omitempty"`
	Name    string         `json:"name,omitempty"`
	Size    uint64         `json:"size,omitempty"`
	Score   int            `json:"score,omitempty"`
	Band    string         `json:"band,omitempty"`
	Reasons []ReasonPoints `json:"reasons,omitempty"`

	// UserHash and Address are the publisher: of the offer for a file, of the session
	// for a publisher. Files is how many files that session had offered.
	UserHash string `json:"userHash,omitempty"`
	Address  string `json:"address,omitempty"`
	Files    int    `json:"files,omitempty"`

	// Decision is the list the operator put the file on: banlist, filter or whitelist.
	Decision string `json:"decision,omitempty"`
}

// verdictLog appends LogEntry lines to a file. A nil *verdictLog writes nothing.
type verdictLog struct {
	mu     sync.Mutex
	path   string
	file   *os.File
	size   int64
	max    int64
	failed bool
}

func openVerdictLog(path string) (*verdictLog, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	l := &verdictLog{path: path, max: maxVerdictLogBytes}
	if err := l.open(); err != nil {
		return nil, err
	}
	return l, nil
}

func (l *verdictLog) open() error {
	file, err := os.OpenFile(l.path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return err
	}
	l.file, l.size = file, info.Size()
	return nil
}

// write appends one entry. A failure is logged once and the entry lost: the verdict
// log must never be why an offer is not handled.
func (l *verdictLog) write(now time.Time, e LogEntry) {
	if l == nil {
		return
	}
	e.Time = now.UTC().Format(time.RFC3339)
	line, err := json.Marshal(e)
	if err != nil {
		return
	}
	line = append(line, '\n')
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil {
		return
	}
	if l.size+int64(len(line)) > l.max {
		err = l.rotate()
	}
	if err == nil {
		var n int
		n, err = l.file.Write(line)
		l.size += int64(n)
	}
	if err != nil && !l.failed {
		l.failed = true
		logging.Errorf("spam detection: verdict log %s not written: %v", l.path, err)
	}
}

// rotate moves the full log aside and starts a new one.
func (l *verdictLog) rotate() error {
	_ = l.file.Close()
	l.file = nil
	if err := os.Rename(l.path, l.path+".1"); err != nil {
		return err
	}
	return l.open()
}

func (l *verdictLog) close() {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file != nil {
		_ = l.file.Close()
		l.file = nil
	}
}
