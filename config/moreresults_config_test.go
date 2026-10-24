package config

import (
	"testing"
	"time"
)

// TestMoreResultsDefaults covers tcp.moreResults: absent keys keep two pages for five
// minutes, an explicit 0 turns paging off, too many rows are clamped to what a search
// returns, and a TTL of 0 or less falls back to the default.
func TestMoreResultsDefaults(t *testing.T) {
	ptr := func(v int) *int { return &v }
	cases := []struct {
		name     string
		in       MoreResultsConfig
		wantRows int
		wantTTL  time.Duration
	}{
		{"absent", MoreResultsConfig{}, 510, 5 * time.Minute},
		{"paging off", MoreResultsConfig{MaxRows: ptr(0)}, 0, 5 * time.Minute},
		{"one page, one minute", MoreResultsConfig{MaxRows: ptr(255), TTLSeconds: ptr(60)}, 255, time.Minute},
		{"clamped", MoreResultsConfig{MaxRows: ptr(5000)}, 745, 5 * time.Minute},
		{"negative rows", MoreResultsConfig{MaxRows: ptr(-3)}, 0, 5 * time.Minute},
		{"zero ttl", MoreResultsConfig{TTLSeconds: ptr(0)}, 510, 5 * time.Minute},
	}
	for _, c := range cases {
		rows, ttl := c.in.MaxRowsOrDefault(), c.in.TTLOrDefault()
		t.Logf("case=%q -> maxRows=%d ttl=%s", c.name, rows, ttl)
		if rows != c.wantRows || ttl != c.wantTTL {
			t.Errorf("%s: got %d/%s, want %d/%s", c.name, rows, ttl, c.wantRows, c.wantTTL)
		}
	}
}
