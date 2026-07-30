package config

import (
	"path/filepath"
	"testing"
)

// TestStorageSnapshotDefaultsOff guards the opt-in. Persisting the index writes a
// potentially very large file on a timer, so an operator who has not asked for it
// must not get it — and an absent key is exactly the false a plain bool yields.
func TestStorageSnapshotDefaultsOff(t *testing.T) {
	cfg := writeConfig(t, "address: 127.0.0.1\n")
	t.Logf("input:  a config with no storage.snapshot section")
	t.Logf("output: enabled=%v file=%q intervalMinutes=%d compress=%v",
		cfg.Storage.Snapshot.Enabled, cfg.Storage.Snapshot.File,
		cfg.Storage.Snapshot.IntervalMinutes, cfg.Storage.Snapshot.Compress)

	if cfg.Storage.Snapshot.Enabled {
		t.Fatal("storage.snapshot must default to off")
	}
}

// TestStorageSnapshotDefaults pins the values an omitted key resolves to, including
// the DataDir placement rule: the server writes this file, so it belongs under
// data/ alongside server.met rather than beside the binary.
func TestStorageSnapshotDefaults(t *testing.T) {
	cfg := writeConfig(t, "address: 127.0.0.1\n")
	wantFile := filepath.Join(DataDir, "storage.gob")

	t.Logf("input:  a config with no storage.snapshot section")
	t.Logf("output: file=%q intervalMinutes=%d", cfg.Storage.Snapshot.File, cfg.Storage.Snapshot.IntervalMinutes)

	if cfg.Storage.Snapshot.File != wantFile {
		t.Fatalf("file = %q, want %q", cfg.Storage.Snapshot.File, wantFile)
	}
	if cfg.Storage.Snapshot.IntervalMinutes != 15 {
		t.Fatalf("intervalMinutes = %d, want 15", cfg.Storage.Snapshot.IntervalMinutes)
	}
	if resolved := cfg.StorageSnapshotPath(); resolved == "" {
		t.Fatal("StorageSnapshotPath must resolve a non-empty path")
	}
}

// TestStorageSnapshotExplicitValuesWin checks the keys are actually read, including
// a non-positive interval falling back to the default rather than producing a
// ticker that fires continuously.
func TestStorageSnapshotExplicitValuesWin(t *testing.T) {
	cases := []struct {
		name         string
		body         string
		wantEnabled  bool
		wantInterval int
		wantCompress bool
		wantFile     string
	}{
		{
			name: "explicit values",
			body: "address: 127.0.0.1\nstorage:\n  snapshot:\n    enabled: true\n" +
				"    file: \"data/custom.gob\"\n    intervalMinutes: 5\n    compress: false\n",
			wantEnabled:  true,
			wantInterval: 5,
			wantCompress: false,
			wantFile:     "data/custom.gob",
		},
		{
			name: "zero interval falls back",
			body: "address: 127.0.0.1\nstorage:\n  snapshot:\n    enabled: true\n" +
				"    intervalMinutes: 0\n",
			wantEnabled:  true,
			wantInterval: 15,
			wantCompress: false,
			wantFile:     filepath.Join(DataDir, "storage.gob"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := writeConfig(t, tc.body)
			t.Logf("input:  %q", tc.body)
			t.Logf("output: enabled=%v file=%q intervalMinutes=%d compress=%v",
				cfg.Storage.Snapshot.Enabled, cfg.Storage.Snapshot.File,
				cfg.Storage.Snapshot.IntervalMinutes, cfg.Storage.Snapshot.Compress)

			if cfg.Storage.Snapshot.Enabled != tc.wantEnabled {
				t.Errorf("enabled = %v, want %v", cfg.Storage.Snapshot.Enabled, tc.wantEnabled)
			}
			if cfg.Storage.Snapshot.File != tc.wantFile {
				t.Errorf("file = %q, want %q", cfg.Storage.Snapshot.File, tc.wantFile)
			}
			if cfg.Storage.Snapshot.IntervalMinutes != tc.wantInterval {
				t.Errorf("intervalMinutes = %d, want %d", cfg.Storage.Snapshot.IntervalMinutes, tc.wantInterval)
			}
			if cfg.Storage.Snapshot.Compress != tc.wantCompress {
				t.Errorf("compress = %v, want %v", cfg.Storage.Snapshot.Compress, tc.wantCompress)
			}
		})
	}
}
