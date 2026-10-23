package spamfilter

import (
	"encoding/json"
	"sync"
	"time"

	"enode/logging"
)

// LogEntry is one line of the verdict log, a JSON object. Type says which fields are
// set: "file" for a scored file, "publisher" for a flagged session, and "decision" for
// what the operator did with a file. A line of Type "truncated" starts a file emptied at
// its size limit, filter.spam.logRotate.enabled being false.
type LogEntry struct {
	Time string `json:"time"`
	Type string `json:"type"`

	Hash    string         `json:"hash,omitempty"`
	Name    string         `json:"name,omitempty"`
	Size    uint64         `json:"size,omitempty"`
	Score   int            `json:"score,omitempty"`
	Band    string         `json:"band,omitempty"`
	Reasons []ReasonPoints `json:"reasons,omitempty"`

	// FileType, LengthSec, BitrateKbps and Codec are the tags the publisher sent with a
	// file, the input of the media reasons.
	FileType    string `json:"fileType,omitempty"`
	LengthSec   uint32 `json:"lengthSec,omitempty"`
	BitrateKbps uint32 `json:"bitrateKbps,omitempty"`
	Codec       string `json:"codec,omitempty"`

	// UserHash and Address are the publisher: of the offer for a file, of the session
	// for a publisher. Files is how many files that session had offered.
	UserHash string `json:"userHash,omitempty"`
	Address  string `json:"address,omitempty"`
	Files    int    `json:"files,omitempty"`

	// Decision is the list the operator put the file on: banlist, filter or whitelist.
	Decision string `json:"decision,omitempty"`
}

// verdictLog appends LogEntry lines to a file, bounded by filter.spam.logRotate. A nil
// *verdictLog writes nothing.
type verdictLog struct {
	mu     sync.Mutex
	path   string
	w      logging.ReopenWriter
	failed bool
}

func openVerdictLog(path string, opts logging.RotateOptions) (*verdictLog, error) {
	// A file emptied at the limit stays JSON lines.
	opts.Marker = `{"type":"truncated"}` + "\n"
	w, err := logging.NewSizeLimitedWriter(path, opts)
	if err != nil {
		return nil, err
	}
	// Opened now rather than on the first entry, so a bad path fails here.
	if _, err := w.Write(nil); err != nil {
		return nil, err
	}
	return &verdictLog{path: path, w: w}, nil
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
	if l.w == nil {
		return
	}
	if _, err = l.w.Write(line); err != nil && !l.failed {
		l.failed = true
		logging.Errorf("spam detection: verdict log %s not written: %v", l.path, err)
	}
}

// reopen closes the file; the next entry opens its path again.
func (l *verdictLog) reopen() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.w == nil {
		return nil
	}
	return l.w.Reopen()
}

func (l *verdictLog) close() {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.w != nil {
		_ = l.w.Close()
		l.w = nil
	}
}
