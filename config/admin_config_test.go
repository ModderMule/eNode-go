package config

import "testing"

// TestAdminEnabledOrDefault covers the *bool absent-≠-false toggle: an omitted key
// must default the dashboard on, while an explicit false must turn it off.
func TestAdminEnabledOrDefault(t *testing.T) {
	f, tr := false, true
	cases := []struct {
		name string
		in   *bool
		want bool
	}{
		{"absent defaults on", nil, true},
		{"explicit false honoured", &f, false},
		{"explicit true honoured", &tr, true},
	}
	for _, c := range cases {
		got := AdminConfig{Enabled: c.in}.EnabledOrDefault()
		t.Logf("case=%q enabled=%v -> EnabledOrDefault=%v", c.name, c.in, got)
		if got != c.want {
			t.Errorf("%s: EnabledOrDefault()=%v, want %v", c.name, got, c.want)
		}
	}
}

// TestAdminDefaults verifies setDefaults fills the loopback bind and the 4560 port
// when the keys are omitted, and preserves values the operator set explicitly.
func TestAdminDefaults(t *testing.T) {
	t.Run("defaults applied when omitted", func(t *testing.T) {
		cfg := Config{}
		if err := setDefaults(&cfg); err != nil {
			t.Fatalf("setDefaults: %v", err)
		}
		t.Logf("input: admin{} -> bindIP=%q port=%d", cfg.Admin.BindIP, cfg.Admin.Port)
		if cfg.Admin.BindIP != "127.0.0.1" {
			t.Errorf("BindIP=%q, want 127.0.0.1", cfg.Admin.BindIP)
		}
		if cfg.Admin.Port != 4560 {
			t.Errorf("Port=%d, want 4560", cfg.Admin.Port)
		}
	})

	t.Run("explicit values preserved", func(t *testing.T) {
		cfg := Config{Admin: AdminConfig{BindIP: "0.0.0.0", Port: 9000}}
		if err := setDefaults(&cfg); err != nil {
			t.Fatalf("setDefaults: %v", err)
		}
		t.Logf("input: admin{bindIP:0.0.0.0 port:9000} -> bindIP=%q port=%d", cfg.Admin.BindIP, cfg.Admin.Port)
		if cfg.Admin.BindIP != "0.0.0.0" || cfg.Admin.Port != 9000 {
			t.Errorf("explicit admin config not preserved: bindIP=%q port=%d", cfg.Admin.BindIP, cfg.Admin.Port)
		}
	})
}
