package config

import (
	"os"
	"path/filepath"
	"testing"
)

// storage.countCacheSeconds defaults to a minute, keeps an explicit value, and
// treats zero or a negative value as unset.
func TestCountCacheSeconds(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want int
	}{
		{"unset", "", 60},
		{"explicit", "  countCacheSeconds: 300\n", 300},
		{"zero", "  countCacheSeconds: 0\n", 60},
		{"negative", "  countCacheSeconds: -5\n", 60},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "enode.config.yaml")
			body := "address: 127.0.0.1\nstorage:\n  engine: memory\n" + c.yaml
			if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
			cfg, err := Load(path)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("input: %q", c.yaml)
			t.Logf("output: CountCacheSeconds=%d OrDefault=%d", cfg.Storage.CountCacheSeconds, cfg.Storage.CountCacheSecondsOrDefault())
			if got := cfg.Storage.CountCacheSecondsOrDefault(); got != c.want {
				t.Fatalf("CountCacheSecondsOrDefault=%d, want %d", got, c.want)
			}
		})
	}

	var zero StorageConfig
	if got := zero.CountCacheSecondsOrDefault(); got != DefaultCountCacheSeconds {
		t.Fatalf("zero value gives %d, want %d", got, DefaultCountCacheSeconds)
	}
}
