package config

import (
	"os"
	"path/filepath"
	"testing"

	"enode/logging"
)

// logRotate left out gets 500 MB, rotation on, one backup and no compression, for the
// server log and the spam verdict log alike; set values are kept.
func TestLogRotateDefaults(t *testing.T) {
	for _, tc := range []struct {
		yaml string
		want logging.RotateOptions
	}{
		{yaml: "", want: logging.RotateOptions{MaxSizeMB: 500, Rotate: true, MaxBackups: 1}},
		{yaml: "logRotate:\n  maxSizeMB: 0\n  maxBackups: 0\n", want: logging.RotateOptions{MaxSizeMB: 500, Rotate: true, MaxBackups: 1}},
		{yaml: "logRotate:\n  maxSizeMB: 20\n  enabled: false\n", want: logging.RotateOptions{MaxSizeMB: 20, MaxBackups: 1}},
		{yaml: "logRotate:\n  maxSizeMB: -1\n", want: logging.RotateOptions{MaxSizeMB: -1, Rotate: true, MaxBackups: 1}},
		{yaml: "logRotate:\n  maxBackups: 3\n  compress: true\n", want: logging.RotateOptions{MaxSizeMB: 500, Rotate: true, MaxBackups: 3, Compress: true}},
	} {
		path := filepath.Join(t.TempDir(), "enode.config.yaml")
		if err := os.WriteFile(path, []byte("address: 127.0.0.1\n"+tc.yaml), 0o644); err != nil {
			t.Fatal(err)
		}
		cfg, err := Load(path)
		if err != nil {
			t.Fatal(err)
		}
		got, spam := cfg.LogRotate.Options(), cfg.Filter.Spam.LogRotate.Options()
		t.Logf("input: %q; output: logRotate=%+v filter.spam.logRotate=%+v", tc.yaml, got, spam)
		if got != tc.want {
			t.Errorf("logRotate = %+v, want %+v", got, tc.want)
		}
		if def := (logging.RotateOptions{MaxSizeMB: 500, Rotate: true, MaxBackups: 1}); spam != def {
			t.Errorf("filter.spam.logRotate = %+v, want the defaults %+v", spam, def)
		}
	}
}
