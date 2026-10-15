package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"enode/config"
	"enode/storage"
)

// planHandoff reads handoff.memory from the config file as it is when the signal
// arrives, applies it to the memory engine only, and falls back to the boot
// config when the file no longer loads.
func TestPlanHandoff(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "enode.config.yaml")
	write := func(mode string) {
		body := "address: 127.0.0.1\nstorage:\n  snapshot:\n    file: " + filepath.Join(dir, "storage.gob") +
			"\nhandoff:\n  memory: " + mode + "\n"
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	memory := storage.NewMemoryEngine()
	mysql, err := storage.NewMySQLEngine(storage.MySQLConfig{Host: "h", Port: 1, User: "u", Database: "d"})
	if err != nil {
		t.Fatal(err)
	}
	boot := config.Config{Handoff: config.HandoffConfig{Memory: config.HandoffMemoryOff}}

	for _, tc := range []struct {
		mode     string
		engine   storage.Engine
		wantFile string
		wantErr  error
	}{
		{mode: "stream", engine: memory},
		{mode: "file", engine: memory, wantFile: filepath.Join(dir, "storage.gob.handoff")},
		{mode: `"off"`, engine: memory, wantErr: errHandoffOff},
		// A database engine moves almost nothing, so the setting does not apply.
		{mode: `"off"`, engine: mysql},
		{mode: "file", engine: mysql},
		// Unloadable: the boot config ("off") decides.
		{mode: "bogus", engine: memory, wantErr: errHandoffOff},
	} {
		write(tc.mode)
		plan, err := planHandoff(handoffDeps{engine: tc.engine, configPath: path, boot: boot})
		t.Logf("input: memory=%s engine=%T; output: file=%q err=%v", tc.mode, tc.engine, plan.file, err)
		if !errors.Is(err, tc.wantErr) || plan.file != tc.wantFile {
			t.Fatalf("plan %+v err %v, want file %q err %v", plan, err, tc.wantFile, tc.wantErr)
		}
	}
}
