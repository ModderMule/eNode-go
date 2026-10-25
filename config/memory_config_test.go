package config

import "testing"

func TestMemoryAndCacheByteDefaults(t *testing.T) {
	cfg := Config{}
	if err := setDefaults(&cfg); err != nil {
		t.Fatalf("setDefaults: %v", err)
	}
	m := cfg.Memory
	t.Logf("input: empty config; output: memory=%+v enabled=%t metaSearch.cache.maxBytes=%d metaApi.search.cache.maxBytes=%d",
		m, m.EnabledOrDefault(), cfg.MetaSearch.Cache.MaxBytes, cfg.MetaAPI.Search.Cache.MaxBytes)
	if !m.EnabledOrDefault() || m.LimitBytes != 0 || m.AutoPercent != 75 || m.ShedAtPercent != 80 || m.KeepPercent != 50 {
		t.Errorf("memory defaults: %+v", m)
	}
	if cfg.MetaSearch.Cache.MaxBytes != 256<<20 || cfg.MetaAPI.Search.Cache.MaxBytes != 256<<20 {
		t.Errorf("cache maxBytes defaults: metaSearch=%d metaApi=%d, want 256 MiB",
			cfg.MetaSearch.Cache.MaxBytes, cfg.MetaAPI.Search.Cache.MaxBytes)
	}
}

func TestMemoryConfigRejectsOutOfRange(t *testing.T) {
	cases := []MemoryConfig{
		{LimitBytes: -1},
		{AutoPercent: 101},
		{ShedAtPercent: -5},
		{KeepPercent: 100},
	}
	for _, c := range cases {
		err := setMemoryDefaults(&c)
		t.Logf("input: %+v; output: err=%v", c, err)
		if err == nil {
			t.Errorf("%+v accepted", c)
		}
	}
	ok := MemoryConfig{LimitBytes: 1 << 30, AutoPercent: 60, ShedAtPercent: 90, KeepPercent: 25}
	if err := setMemoryDefaults(&ok); err != nil || ok.AutoPercent != 60 || ok.KeepPercent != 25 {
		t.Errorf("explicit values: %+v err=%v", ok, err)
	}
}
