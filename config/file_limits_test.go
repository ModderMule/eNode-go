package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeFileLimitsConfig writes a minimal config carrying only the given files: block
// body (which may be empty, meaning the key is absent entirely).
func writeFileLimitsConfig(t *testing.T, filesBlock string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "enode.config.yaml")
	body := "address: 127.0.0.1\nstorage:\n  engine: memory\n" + filesBlock
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestFileLimitsDefaultWhenAbsent pins the defaults for a YAML with no files: block —
// the values eNode-go has always advertised, so an existing config keeps its wire
// behaviour and gains enforcement.
func TestFileLimitsDefaultWhenAbsent(t *testing.T) {
	cfg, err := Load(writeFileLimitsConfig(t, ""))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("input: config with no files: block")
	t.Logf("output: softLimit=%d hardLimit=%d", cfg.Files.SoftLimitOrDefault(), cfg.Files.HardLimitOrDefault())

	if got := cfg.Files.SoftLimitOrDefault(); got != DefaultSoftFileLimit {
		t.Errorf("softLimit = %d, want %d", got, DefaultSoftFileLimit)
	}
	if got := cfg.Files.HardLimitOrDefault(); got != DefaultHardFileLimit {
		t.Errorf("hardLimit = %d, want %d", got, DefaultHardFileLimit)
	}
}

// TestFileLimitsExplicitZeroMeansUnlimited is the test that justifies the *int fields.
//
// Zero is a meaningful value here — it turns a cap off — so it must survive defaulting.
// With plain ints and an `if x <= 0 { x = default }` rule, an operator who writes 0
// meaning "unlimited" would silently get 10000 instead.
func TestFileLimitsExplicitZeroMeansUnlimited(t *testing.T) {
	cfg, err := Load(writeFileLimitsConfig(t, "files:\n  softLimit: 0\n  hardLimit: 0\n"))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("input: files.softLimit = 0, files.hardLimit = 0")
	t.Logf("output: softLimit=%d hardLimit=%d", cfg.Files.SoftLimitOrDefault(), cfg.Files.HardLimitOrDefault())

	if got := cfg.Files.SoftLimitOrDefault(); got != 0 {
		t.Errorf("softLimit = %d, want 0 — an explicit zero must not be defaulted away", got)
	}
	if got := cfg.Files.HardLimitOrDefault(); got != 0 {
		t.Errorf("hardLimit = %d, want 0 — an explicit zero must not be defaulted away", got)
	}
}

// TestFileLimitsExplicitValuesWin confirms configured caps survive defaulting.
func TestFileLimitsExplicitValuesWin(t *testing.T) {
	cfg, err := Load(writeFileLimitsConfig(t, "files:\n  softLimit: 500\n  hardLimit: 900\n"))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("input: files.softLimit = 500, files.hardLimit = 900")
	t.Logf("output: softLimit=%d hardLimit=%d", cfg.Files.SoftLimitOrDefault(), cfg.Files.HardLimitOrDefault())

	if got := cfg.Files.SoftLimitOrDefault(); got != 500 {
		t.Errorf("softLimit = %d, want 500", got)
	}
	if got := cfg.Files.HardLimitOrDefault(); got != 900 {
		t.Errorf("hardLimit = %d, want 900", got)
	}
}

// TestFileLimitsRejectHardBelowSoft pins the fail-fast validation. The two are checked
// in hard-then-soft order per record, so a hard limit under the soft one kills the
// session before the warning could ever be sent — the operator has written a soft limit
// that can never fire, and nothing would tell them.
func TestFileLimitsRejectHardBelowSoft(t *testing.T) {
	_, err := Load(writeFileLimitsConfig(t, "files:\n  softLimit: 1000\n  hardLimit: 500\n"))
	t.Logf("input: files.softLimit = 1000, files.hardLimit = 500")
	t.Logf("output: err=%v", err)

	if err == nil {
		t.Fatal("hardLimit below softLimit loaded successfully, want a load error")
	}
	if !strings.Contains(err.Error(), "files.hardLimit") || !strings.Contains(err.Error(), "files.softLimit") {
		t.Errorf("error %q names neither key; an operator needs to know which to change", err)
	}
}

// TestFileLimitsAllowHardEqualToSoft: degenerate but coherent — "warn at N, drop at N"
// collapses to dropping at N, because the hard check runs first. Legal, not an error.
func TestFileLimitsAllowHardEqualToSoft(t *testing.T) {
	cfg, err := Load(writeFileLimitsConfig(t, "files:\n  softLimit: 750\n  hardLimit: 750\n"))
	t.Logf("input: files.softLimit = files.hardLimit = 750")
	t.Logf("output: err=%v", err)
	if err != nil {
		t.Fatalf("equal limits should load: %v", err)
	}
	if cfg.Files.SoftLimitOrDefault() != 750 || cfg.Files.HardLimitOrDefault() != 750 {
		t.Errorf("limits = %d/%d, want 750/750",
			cfg.Files.SoftLimitOrDefault(), cfg.Files.HardLimitOrDefault())
	}
}

// TestFileLimitsRejectNegative: a negative cap is a typo. It cannot mean "unlimited" —
// that is what 0 is for — and it would wrap to ~4 billion in the uint32 wire field.
func TestFileLimitsRejectNegative(t *testing.T) {
	_, err := Load(writeFileLimitsConfig(t, "files:\n  softLimit: -1\n  hardLimit: 4000\n"))
	t.Logf("input: files.softLimit = -1")
	t.Logf("output: err=%v", err)

	if err == nil {
		t.Fatal("a negative softLimit loaded successfully, want a load error")
	}
}

// TestFileLimitsUnlimitedHardWithSoftCap: soft on, hard off is a supported combination —
// warn and trim forever, never disconnect. The hard==0 branch must not be caught by the
// hard-below-soft check.
func TestFileLimitsUnlimitedHardWithSoftCap(t *testing.T) {
	cfg, err := Load(writeFileLimitsConfig(t, "files:\n  softLimit: 1000\n  hardLimit: 0\n"))
	t.Logf("input: files.softLimit = 1000, files.hardLimit = 0 (unlimited)")
	t.Logf("output: err=%v softLimit=%d hardLimit=%d", err,
		cfg.Files.SoftLimitOrDefault(), cfg.Files.HardLimitOrDefault())

	if err != nil {
		t.Fatalf("soft cap with an unlimited hard limit should load: %v", err)
	}
	if cfg.Files.SoftLimitOrDefault() != 1000 || cfg.Files.HardLimitOrDefault() != 0 {
		t.Errorf("limits = %d/%d, want 1000/0",
			cfg.Files.SoftLimitOrDefault(), cfg.Files.HardLimitOrDefault())
	}
}
