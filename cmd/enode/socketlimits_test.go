package main

import (
	"strings"
	"testing"
)

// TestSocketLimitWarnings pins when startup warns about the open-file limit and the
// listen backlog.
func TestSocketLimitWarnings(t *testing.T) {
	cases := []struct {
		name           string
		maxConnections int
		fdLimit        uint64
		somaxconn      int
		want           []string // substrings, one per warning
	}{
		{"systemd default hard limit", 1000000, 524288, 4096, nil},
		{"macOS default", 0, 24576, 0, nil},
		{"shell default 1024", 1000000, 1024, 4096, []string{"open file limit is 1024, below the 16640"}},
		{"small server fits", 500, 1024, 4096, nil},
		{"small server over", 1000, 1024, 4096, []string{"below the 1256 that 1000 sessions"}},
		{"old kernel backlog", 1000000, 524288, 128, []string{"somaxconn is 128"}},
		{"both unknown", 1000000, 0, 0, nil},
	}
	for _, tc := range cases {
		got := socketLimitWarnings(tc.maxConnections, tc.fdLimit, tc.somaxconn)
		t.Logf("input: %s maxConnections=%d fd=%d somaxconn=%d, output: %q",
			tc.name, tc.maxConnections, tc.fdLimit, tc.somaxconn, got)
		if len(got) != len(tc.want) {
			t.Fatalf("%s: %d warnings, want %d", tc.name, len(got), len(tc.want))
		}
		for i, w := range tc.want {
			if !strings.Contains(got[i], w) {
				t.Errorf("%s: warning %q lacks %q", tc.name, got[i], w)
			}
		}
	}
}
