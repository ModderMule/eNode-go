package config

import (
	"strings"
	"testing"
)

func TestOfferFilesV1Defaults(t *testing.T) {
	cfg, err := Load(writeFileLimitsConfig(t, ""))
	if err != nil {
		t.Fatal(err)
	}
	v1 := cfg.Files.OfferFilesV1
	t.Logf("input: no files: block output: enabled=%t batchMax=%d minIntervalMs=%d",
		v1.EnabledOrDefault(), v1.BatchMaxOrDefault(), v1.MinIntervalMsOrDefault())
	if !v1.EnabledOrDefault() || v1.BatchMaxOrDefault() != DefaultOfferFilesV1BatchMax ||
		v1.MinIntervalMsOrDefault() != DefaultOfferFilesV1MinIntervalMs {
		t.Errorf("defaults = %t/%d/%d", v1.EnabledOrDefault(), v1.BatchMaxOrDefault(), v1.MinIntervalMsOrDefault())
	}
}

func TestOfferFilesV1Validation(t *testing.T) {
	cases := []struct {
		name, block, wantErr string
	}{
		{"valid", "files:\n  offerFilesV1:\n    batchMax: 100\n    minIntervalMs: 250\n", ""},
		{"batch 0", "files:\n  offerFilesV1:\n    batchMax: 0\n", "batchMax"},
		{"interval 0", "files:\n  offerFilesV1:\n    minIntervalMs: 0\n", "minIntervalMs"},
		{"interval above legacy pace", "files:\n  offerFilesV1:\n    minIntervalMs: 60001\n", "minIntervalMs"},
		{"batch not below hard", "files:\n  hardLimit: 200\n", "below files.hardLimit"},
		{"unlimited limits are not an error", "files:\n  softLimit: 0\n  hardLimit: 0\n", ""},
		{"off skips checks", "files:\n  offerFilesV1:\n    enabled: false\n    batchMax: 0\n", ""},
	}
	for _, tc := range cases {
		_, err := Load(writeFileLimitsConfig(t, tc.block))
		t.Logf("input: %s %q output: err=%v", tc.name, tc.block, err)
		switch {
		case tc.wantErr == "" && err != nil:
			t.Errorf("%s: unexpected error %v", tc.name, err)
		case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
			t.Errorf("%s: err=%v, want one mentioning %q", tc.name, err, tc.wantErr)
		}
	}
}
