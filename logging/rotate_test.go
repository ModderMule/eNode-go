package logging

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// line is about 1 KiB, so a few thousand writes cross the 1 MB limit.
var line = []byte(strings.Repeat("x", 1023) + "\n")

// TestTruncateAtLimit: with rotation off the file is emptied at the limit, starts with
// the marker, and no second file appears.
func TestTruncateAtLimit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "enode.log")
	w, err := NewSizeLimitedWriter(path, RotateOptions{MaxSizeMB: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = w.Close() }()
	writes := 1500 // 1.5 MiB
	for i := 0; i < writes; i++ {
		if _, err := w.Write(line); err != nil {
			t.Fatal(err)
		}
	}
	raw, _ := os.ReadFile(path)
	files, _ := os.ReadDir(dir)
	first, _, _ := strings.Cut(string(raw), "\n")
	t.Logf("input: %d x 1 KiB, limit 1 MB, rotation off output: %d bytes, %d files, first line %q", writes, len(raw), len(files), first)
	if len(raw) > 1<<20 || len(files) != 1 {
		t.Errorf("size=%d files=%d, want one file within 1 MiB", len(raw), len(files))
	}
	if first != "log truncated at 1 MB limit (logRotate.enabled=false)" {
		t.Errorf("first line = %q, want the truncation marker", first)
	}
}

// TestTruncateOversizedFileOnOpen: a file already over the limit when the server starts
// is emptied on the first write.
func TestTruncateOversizedFileOnOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "enode.log")
	if err := os.WriteFile(path, bytes.Repeat(line, 1100), 0o644); err != nil {
		t.Fatal(err)
	}
	w, err := NewSizeLimitedWriter(path, RotateOptions{MaxSizeMB: 1})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Write([]byte("after restart\n"))
	_ = w.Close()
	raw, _ := os.ReadFile(path)
	t.Logf("input: existing 1100 KiB file, limit 1 MB output: %q", raw)
	if !strings.HasSuffix(string(raw), "after restart\n") || len(raw) > 200 {
		t.Errorf("file = %q, want the marker and the new line only", raw)
	}
}

// TestRotateKeepsOneBackup: with rotation on, several rotations leave the current file
// and exactly one backup.
func TestRotateKeepsOneBackup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "enode.log")
	w, err := NewSizeLimitedWriter(path, RotateOptions{MaxSizeMB: 1, Rotate: true, MaxBackups: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = w.Close() }()
	writes := 3500 // three rotations
	for i := 0; i < writes; i++ {
		if _, err := w.Write(line); err != nil {
			t.Fatal(err)
		}
	}
	backups := waitForFiles(t, filepath.Join(dir, "enode-*.log"), 1)
	info, _ := os.Stat(path)
	t.Logf("input: %d x 1 KiB, limit 1 MB, 1 backup output: current %d bytes, backups %v", writes, info.Size(), backups)
	if len(backups) != 1 || info.Size() > 1<<20 {
		t.Errorf("backups=%v size=%d, want one backup and a bounded current file", backups, info.Size())
	}
}

// TestRotateCompress: with compress on, the backup becomes a .gz file.
func TestRotateCompress(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "enode.log")
	w, err := NewSizeLimitedWriter(path, RotateOptions{MaxSizeMB: 1, Rotate: true, MaxBackups: 1, Compress: true})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = w.Close() }()
	for i := 0; i < 1100; i++ {
		if _, err := w.Write(line); err != nil {
			t.Fatal(err)
		}
	}
	gz := waitForFiles(t, filepath.Join(dir, "enode-*.log.gz"), 1)
	plain, _ := filepath.Glob(filepath.Join(dir, "enode-*.log"))
	t.Logf("input: 1100 x 1 KiB, limit 1 MB, compress on output: gz=%v uncompressed backups=%v", gz, plain)
	if len(gz) != 1 {
		t.Errorf("gz backups = %v, want one", gz)
	}
}

// TestNoLimit: MaxSizeMB -1 never truncates or rotates.
func TestNoLimit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "enode.log")
	w, err := NewSizeLimitedWriter(path, RotateOptions{MaxSizeMB: -1})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 1200; i++ {
		_, _ = w.Write(line)
	}
	_ = w.Close()
	info, _ := os.Stat(path)
	files, _ := os.ReadDir(dir)
	t.Logf("input: 1200 x 1 KiB, no limit output: %d bytes, %d files", info.Size(), len(files))
	if info.Size() != int64(1200*len(line)) || len(files) != 1 {
		t.Errorf("size=%d files=%d, want every byte in one file", info.Size(), len(files))
	}
}

// TestReopenAfterMove: after an external logrotate moves the file away, Reopen makes
// the next line land in a new file at the original path, for every mode.
func TestReopenAfterMove(t *testing.T) {
	modes := map[string]RotateOptions{
		"rotate":   {MaxSizeMB: 1, Rotate: true, MaxBackups: 1},
		"truncate": {MaxSizeMB: 1},
		"nolimit":  {MaxSizeMB: -1},
	}
	for name, opts := range modes {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "enode.log")
			w, err := NewSizeLimitedWriter(path, opts)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = w.Close() }()
			_, _ = w.Write([]byte("before\n"))
			moved := filepath.Join(dir, "enode.log.moved")
			if err := os.Rename(path, moved); err != nil {
				t.Fatal(err)
			}
			if err := w.Reopen(); err != nil {
				t.Fatal(err)
			}
			_, _ = w.Write([]byte("after\n"))
			cur, _ := os.ReadFile(path)
			old, _ := os.ReadFile(moved)
			t.Logf("input: write, move, Reopen, write (%s) output: current=%q moved=%q", name, cur, old)
			if string(cur) != "after\n" || string(old) != "before\n" {
				t.Errorf("current=%q moved=%q, want the new line in a new file", cur, old)
			}
		})
	}
}

// TestSetOutputAndReopen: the package logger writes through the size-limited writer and
// keeps logging after Reopen.
func TestSetOutputAndReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "enode.log")
	if err := SetOutput(path, RotateOptions{MaxSizeMB: 1, Rotate: true, MaxBackups: 1}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = SetOutputFile("") })
	Infof("first line")
	if err := os.Rename(path, path+".old"); err != nil {
		t.Fatal(err)
	}
	if err := Reopen(); err != nil {
		t.Fatal(err)
	}
	Infof("second line")
	cur, _ := os.ReadFile(path)
	t.Logf("input: Infof, move, Reopen, Infof output: current=%q", cur)
	if !strings.Contains(string(cur), "second line") || strings.Contains(string(cur), "first line") {
		t.Errorf("current file = %q, want only the line after Reopen", cur)
	}
}

// waitForFiles globs until want files match or a second passes: lumberjack removes and
// compresses backups in the background.
func waitForFiles(t *testing.T, pattern string, want int) []string {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		got, _ := filepath.Glob(pattern)
		if len(got) == want || time.Now().After(deadline) {
			return got
		}
		time.Sleep(20 * time.Millisecond)
	}
}
