package config

import "fmt"

// MemoryConfig is the memory guard: a soft memory limit for the Go GC, and cache
// shedding when the live heap nears it, so a load spike drops cached search answers
// instead of running the process out of memory. See docs/memory-guard.md.
type MemoryConfig struct {
	// Enabled is *bool so an absent key means on.
	Enabled *bool `yaml:"enabled"`
	// LimitBytes is the soft limit. 0 takes GOMEMLIMIT when set, else AutoPercent of
	// the cgroup memory limit, else of physical RAM.
	LimitBytes int64 `yaml:"limitBytes"`
	// AutoPercent is the share of cgroup/RAM a detected limit is set to. Default 75.
	AutoPercent int `yaml:"autoPercent"`
	// ShedAtPercent: a live heap above this share of the limit makes caches shed.
	// Default 80.
	ShedAtPercent int `yaml:"shedAtPercent"`
	// KeepPercent is the share of its bytes each cache keeps per shed, expired
	// entries dropped first. Default 50.
	KeepPercent int `yaml:"keepPercent"`
}

// EnabledOrDefault reports whether the guard runs, defaulting to true.
func (c MemoryConfig) EnabledOrDefault() bool {
	return boolOrDefault(c.Enabled, true)
}

func setMemoryDefaults(c *MemoryConfig) error {
	if c.LimitBytes < 0 {
		return fmt.Errorf("memory.limitBytes must not be negative")
	}
	if c.AutoPercent == 0 {
		c.AutoPercent = 75
	}
	if c.ShedAtPercent == 0 {
		c.ShedAtPercent = 80
	}
	if c.KeepPercent == 0 {
		c.KeepPercent = 50
	}
	for _, p := range []struct {
		key      string
		value    int
		min, max int
	}{
		{"memory.autoPercent", c.AutoPercent, 1, 100},
		{"memory.shedAtPercent", c.ShedAtPercent, 1, 100},
		{"memory.keepPercent", c.KeepPercent, 0, 99},
	} {
		if p.value < p.min || p.value > p.max {
			return fmt.Errorf("%s must be between %d and %d", p.key, p.min, p.max)
		}
	}
	return nil
}
