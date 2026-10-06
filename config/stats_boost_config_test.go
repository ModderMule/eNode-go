package config

import (
	"strings"
	"testing"
)

// TestStatsBoostAbsentIsZero pins that a config without the section — the published
// one — advertises real counts: every offset is 0.
func TestStatsBoostAbsentIsZero(t *testing.T) {
	cfg, err := Load(writeFileLimitsConfig(t, ""))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("input: config with no statsBoost: block")
	t.Logf("output: statsBoost=%+v", cfg.StatsBoost)
	if cfg.StatsBoost != (StatsBoostConfig{}) {
		t.Errorf("statsBoost = %+v, want all zero", cfg.StatsBoost)
	}
}

// TestStatsBoostParsed checks the three keys load as written.
func TestStatsBoostParsed(t *testing.T) {
	block := "statsBoost:\n  users: 40001\n  lowIDUsers: 1000\n  files: 5000001\n"
	cfg, err := Load(writeFileLimitsConfig(t, block))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("input: %q", block)
	t.Logf("output: statsBoost=%+v", cfg.StatsBoost)
	want := StatsBoostConfig{Users: 40001, LowIDUsers: 1000, Files: 5000001}
	if cfg.StatsBoost != want {
		t.Errorf("statsBoost = %+v, want %+v", cfg.StatsBoost, want)
	}
}

// TestStatsBoostNetworkUsersParsed checks the two network switches load, and that
// they are off when the section sets only the offsets.
func TestStatsBoostNetworkUsersParsed(t *testing.T) {
	cases := []struct {
		block string
		want  StatsBoostConfig
	}{
		{"statsBoost:\n  users: 5\n", StatsBoostConfig{Users: 5}},
		{"statsBoost:\n  kadUsers: true\n", StatsBoostConfig{KadUsers: true}},
		{"statsBoost:\n  torrentUsers: true\n", StatsBoostConfig{TorrentUsers: true}},
		{"statsBoost:\n  users: 5\n  kadUsers: true\n  torrentUsers: true\n",
			StatsBoostConfig{Users: 5, KadUsers: true, TorrentUsers: true}},
	}
	for _, tc := range cases {
		cfg, err := Load(writeFileLimitsConfig(t, tc.block))
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("input: %q -> output: statsBoost=%+v", tc.block, cfg.StatsBoost)
		if cfg.StatsBoost != tc.want {
			t.Errorf("%q: statsBoost = %+v, want %+v", tc.block, cfg.StatsBoost, tc.want)
		}
	}
}

// TestStatsBoostRejectsNegative: a negative offset would make the advertised count
// smaller than the real one, which is never what the section is for.
func TestStatsBoostRejectsNegative(t *testing.T) {
	for _, block := range []string{
		"statsBoost:\n  users: -1\n",
		"statsBoost:\n  lowIDUsers: -1\n",
		"statsBoost:\n  files: -1\n",
	} {
		_, err := Load(writeFileLimitsConfig(t, block))
		t.Logf("input: %q -> output: err=%v", block, err)
		if err == nil || !strings.Contains(err.Error(), "statsBoost") {
			t.Errorf("%q: want a statsBoost error, got %v", block, err)
		}
	}
}
