package logging

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"gopkg.in/natefinch/lumberjack.v2"
)

// DefaultMaxSizeMB is the log size limit when none is configured.
const DefaultMaxSizeMB = 500

// RotateOptions bounds a log file's size.
//
// At the limit, Rotate renames the file to "<name>-<time><ext>" and starts a new one,
// keeping MaxBackups old files (gzipped when Compress is set). Without Rotate the file
// is emptied in place, so only one file ever exists. A negative MaxSizeMB means no
// limit: the file only grows, for operators who rotate it externally.
type RotateOptions struct {
	MaxSizeMB  int
	Rotate     bool
	MaxBackups int
	Compress   bool
	// Marker is the first line of a file emptied at the limit, newline included. Empty
	// writes a plain text line saying so; a JSON-lines file passes a JSON object.
	Marker string
}

// ReopenWriter is a log writer whose file can be closed and reopened at its path, so a
// file moved away by an external logrotate is replaced by a new one.
type ReopenWriter interface {
	io.WriteCloser
	Reopen() error
}

// NewSizeLimitedWriter returns a writer appending to path, bounded as opts says. The
// directory is created. The file is opened on the first write.
func NewSizeLimitedWriter(path string, opts RotateOptions) (ReopenWriter, error) {
	if dir := filepath.Dir(path); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
	}
	switch {
	case opts.MaxSizeMB < 0:
		return &limitedFile{path: path}, nil
	case opts.Rotate:
		backups := opts.MaxBackups
		if backups < 1 {
			// lumberjack reads 0 as "keep every backup", never what is meant here.
			backups = 1
		}
		return &rotatingFile{lj: &lumberjack.Logger{
			Filename:   path,
			MaxSize:    sizeMB(opts.MaxSizeMB),
			MaxBackups: backups,
			Compress:   opts.Compress,
			LocalTime:  true,
		}}, nil
	default:
		mb := sizeMB(opts.MaxSizeMB)
		marker := opts.Marker
		if marker == "" {
			marker = fmt.Sprintf("log truncated at %d MB limit (logRotate.enabled=false)\n", mb)
		}
		return &limitedFile{path: path, maxBytes: int64(mb) << 20, marker: marker}, nil
	}
}

// rotatingFile is lumberjack with Reopen. Closing it is enough: lumberjack reopens the
// path on the next write.
type rotatingFile struct {
	lj *lumberjack.Logger
}

func (r *rotatingFile) Write(p []byte) (int, error) { return r.lj.Write(p) }
func (r *rotatingFile) Close() error                { return r.lj.Close() }
func (r *rotatingFile) Reopen() error               { return r.lj.Close() }

// limitedFile appends to one file. With maxBytes set, a write that would take the file
// past it empties the file first and starts it with marker. maxBytes 0 means no
// limit.
type limitedFile struct {
	path     string
	maxBytes int64
	marker   string

	mu   sync.Mutex
	file *os.File
	size int64
}

func (f *limitedFile) Write(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.file == nil {
		if err := f.open(); err != nil {
			return 0, err
		}
	}
	if f.maxBytes > 0 && f.size+int64(len(p)) > f.maxBytes {
		if err := f.truncate(); err != nil {
			return 0, err
		}
	}
	n, err := f.file.Write(p)
	f.size += int64(n)
	return n, err
}

func (f *limitedFile) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.closeFile()
}

// Reopen closes the file; the next write opens the path again.
func (f *limitedFile) Reopen() error { return f.Close() }

func (f *limitedFile) open() error {
	file, err := os.OpenFile(f.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return err
	}
	f.file, f.size = file, info.Size()
	return nil
}

// truncate empties the file. O_APPEND puts the next write at the new end, offset 0.
func (f *limitedFile) truncate() error {
	if err := f.file.Truncate(0); err != nil {
		return err
	}
	f.size = 0
	n, err := f.file.WriteString(f.marker)
	f.size += int64(n)
	return err
}

func (f *limitedFile) closeFile() error {
	if f.file == nil {
		return nil
	}
	err := f.file.Close()
	f.file = nil
	return err
}

// sizeMB is the configured limit, DefaultMaxSizeMB when unset.
func sizeMB(mb int) int {
	if mb == 0 {
		return DefaultMaxSizeMB
	}
	return mb
}
