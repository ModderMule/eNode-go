package logging

import "testing"

func TestRecentKeepsNewestWarningsAndErrors(t *testing.T) {
	var r recentLog
	for i := 0; i < recentCapacity+5; i++ {
		r.add(LevelWarn, "warning %d", []any{i})
	}
	r.add(LevelError, "last %s", []any{"error"})

	entries, total := r.snapshot(3)
	t.Logf("input: %d warnings then 1 error, limit=3", recentCapacity+5)
	t.Logf("output: total=%d entries=%+v", total, entries)

	if total != recentCapacity+6 {
		t.Fatalf("total = %d, want %d", total, recentCapacity+6)
	}
	if len(entries) != 3 {
		t.Fatalf("len(entries) = %d, want 3", len(entries))
	}
	if entries[0].Message != "last error" || entries[0].Level != LevelError {
		t.Fatalf("newest entry = %+v, want the error", entries[0])
	}
	if entries[1].Message != "warning 204" {
		t.Fatalf("second entry = %q, want warning 204", entries[1].Message)
	}

	all, _ := r.snapshot(0)
	t.Logf("output: unlimited snapshot holds %d entries", len(all))
	if len(all) != recentCapacity {
		t.Fatalf("unlimited snapshot = %d entries, want %d", len(all), recentCapacity)
	}
}

func TestRecentEmpty(t *testing.T) {
	var r recentLog
	entries, total := r.snapshot(10)
	t.Logf("input: empty ring, limit=10; output: total=%d entries=%d", total, len(entries))
	if total != 0 || len(entries) != 0 {
		t.Fatalf("empty ring returned total=%d entries=%d", total, len(entries))
	}
}
