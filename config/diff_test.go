package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// loadDiffConfig writes yaml to a temp file and loads it through Load, so the diff is
// exercised on configs that went through the same defaulting a real reload does.
func loadDiffConfig(t *testing.T, yaml string) Config {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	return cfg
}

const diffBaseYAML = `
name: "before"
tcp:
  port: 5555
  loginTimeout: 20
admin:
  username: "admin"
  password: "old-secret"
gossip:
  enabled: false
  seeds: []
`

func TestDiffReportsChangedKeyPaths(t *testing.T) {
	a := loadDiffConfig(t, diffBaseYAML)
	b := loadDiffConfig(t, `
name: "after"
tcp:
  port: 6666
  loginTimeout: 30
admin:
  username: "admin"
  password: "new-secret"
gossip:
  enabled: true
  seeds:
    - { ip: "203.0.113.7", port: 4661 }
`)
	got := Diff(a, b)
	t.Logf("input: name, tcp.port, tcp.loginTimeout, admin.password, gossip.enabled and gossip.seeds changed")
	t.Logf("output: %v", got)

	// tcp.port moves the derived obfuscated and gossip UDP ports with it.
	want := []string{
		"admin.password", "gossip.enabled", "gossip.seeds", "name",
		"tcp.loginTimeout", "tcp.port", "udp.portGossip", "udp.portObfuscated",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("diff = %v, want %v", got, want)
	}
	for _, p := range got {
		if strings.Contains(p, "secret") || strings.Contains(p, "203.0.113.7") {
			t.Fatalf("diff leaked a value: %q", p)
		}
	}
}

func TestDiffOfIdenticalConfigsIsEmpty(t *testing.T) {
	a := loadDiffConfig(t, diffBaseYAML)
	b := loadDiffConfig(t, diffBaseYAML)
	got := Diff(a, b)
	t.Logf("input: the same file loaded twice")
	t.Logf("output: %v", got)
	if len(got) != 0 {
		t.Fatalf("expected no differences, got %v", got)
	}
}

func TestReloadableClassifiesKeys(t *testing.T) {
	cases := map[string]bool{
		"name":                    true,
		"gossip.enabled":          true,
		"gossip.seeds":            true,
		"statsBoost.users":        true,
		"statsBoost.kadUsers":     true,
		"statsBoost.torrentUsers": true,
		"files.softLimit":         true,
		"tcp.loginTimeout":        true,
		"admin.password":          true,
		"servers":                 true,
		"tcp.port":                false,
		"tcp.maxConnections":      false,
		"udp.portGossip":          false,
		"admin.port":              false,
		"supportCrypt":            false,
		"storage.engine":          false,
		"metaSearch.torrent.url":  false,
		"serverSearch.enabled":    false,
		"serverSearch.peers":      false,
		"metaApi.search.servers":  false,
		"filesystem":              false,
		"gossipExtra":             false,
		"natTraversal.enabled":    false,
		"filter.ipfilter.enabled": false,
	}
	for path, want := range cases {
		got := Reloadable(path)
		t.Logf("input: %q output: reloadable=%t", path, got)
		if got != want {
			t.Errorf("Reloadable(%q) = %t, want %t", path, got, want)
		}
	}
}

// TestOverlayMatchesReloadableKeys pins OverlayReloadable to the reloadableKeys table:
// the overlay must carry over every reloadable key and nothing else. Every field of the
// two configs differs, so a key missing from either side shows up.
func TestOverlayMatchesReloadableKeys(t *testing.T) {
	var base, next Config
	fillDistinct(reflect.ValueOf(&base).Elem(), 1)
	fillDistinct(reflect.ValueOf(&next).Elem(), 2)

	overlay := OverlayReloadable(base, next)
	applied := Diff(base, overlay)
	pending := Diff(overlay, next)
	t.Logf("input: two configs differing in all %d keys", len(Diff(base, next)))
	t.Logf("output: overlay took %d keys from the new config, left %d for a restart", len(applied), len(pending))

	if len(applied) == 0 || len(pending) == 0 {
		t.Fatalf("expected both applied and pending keys, got %d and %d", len(applied), len(pending))
	}
	for _, p := range applied {
		if !Reloadable(p) {
			t.Errorf("overlay applied %q, which is not in reloadableKeys", p)
		}
	}
	for _, p := range pending {
		if Reloadable(p) {
			t.Errorf("%q is in reloadableKeys but the overlay did not apply it", p)
		}
	}
}

// fillDistinct sets every settable scalar under v to a value derived from seed, so two
// configs filled with different seeds differ in every key.
func fillDistinct(v reflect.Value, seed int) {
	switch v.Kind() {
	case reflect.Struct:
		if v.Type().PkgPath() != reflect.TypeOf(Config{}).PkgPath() {
			return
		}
		for i := 0; i < v.NumField(); i++ {
			if v.Type().Field(i).IsExported() {
				fillDistinct(v.Field(i), seed)
			}
		}
	case reflect.Pointer:
		v.Set(reflect.New(v.Type().Elem()))
		fillDistinct(v.Elem(), seed)
	case reflect.Slice:
		v.Set(reflect.MakeSlice(v.Type(), seed, seed))
		for i := 0; i < v.Len(); i++ {
			fillDistinct(v.Index(i), seed)
		}
	case reflect.String:
		v.SetString(strings.Repeat("x", seed))
	case reflect.Bool:
		v.SetBool(seed%2 == 0)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		v.SetInt(int64(seed))
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		v.SetUint(uint64(seed))
	case reflect.Float32, reflect.Float64:
		v.SetFloat(float64(seed))
	}
}
