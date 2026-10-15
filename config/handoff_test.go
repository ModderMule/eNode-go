package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// handoff.memory defaults to "stream", keeps the other two values, and refuses
// anything else at load time rather than falling back to a mode the operator did
// not choose.
func TestHandoffMemoryValues(t *testing.T) {
	for _, tc := range []struct {
		line, want string
		bad        bool
	}{
		{line: "", want: HandoffMemoryStream},
		{line: "handoff:\n  memory: stream\n", want: HandoffMemoryStream},
		{line: "handoff:\n  memory: file\n", want: HandoffMemoryFile},
		{line: "handoff:\n  memory: \"off\"\n", want: HandoffMemoryOff},
		// Unquoted: YAML 1.1 would read a bool, the parser here a string.
		{line: "handoff:\n  memory: off\n", want: HandoffMemoryOff},
		{line: "handoff:\n  memory: disk\n", bad: true},
	} {
		dir := t.TempDir()
		path := filepath.Join(dir, "enode.config.yaml")
		if err := os.WriteFile(path, []byte("address: 127.0.0.1\n"+tc.line), 0o644); err != nil {
			t.Fatal(err)
		}
		cfg, err := Load(path)
		t.Logf("input: %q; output: memory=%q err=%v", tc.line, cfg.Handoff.Memory, err)
		if tc.bad {
			if err == nil || !strings.Contains(err.Error(), "handoff.memory") {
				t.Fatalf("err %v, want a handoff.memory error", err)
			}
			continue
		}
		if err != nil || cfg.Handoff.Memory != tc.want {
			t.Fatalf("memory %q err %v, want %q", cfg.Handoff.Memory, err, tc.want)
		}
	}
}

// The handoff file sits beside the snapshot file.
func TestHandoffFilePath(t *testing.T) {
	cfg := Config{Storage: StorageConfig{Snapshot: SnapshotConfig{File: "/srv/enode/data/storage.gob"}}}
	got := cfg.HandoffFilePath()
	t.Logf("input: snapshot %q; output: %q", cfg.Storage.Snapshot.File, got)
	if got != "/srv/enode/data/storage.gob.handoff" {
		t.Fatalf("HandoffFilePath = %q", got)
	}
}
