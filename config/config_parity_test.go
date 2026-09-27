package config

import (
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// The two shipped configs, relative to this package directory (config/).
const (
	shippedConfigPath = "../enode.config.yaml"
	localConfigPath   = "../enode.local.yaml"
)

// localOnlyConfigKeys are top-level sections that are real config but must never
// appear in the published enode.config.yaml. Both parity tests ignore them and
// everything beneath them. statsBoost inflates advertised counts; see
// config.StatsBoostConfig.
var localOnlyConfigKeys = []string{"statsBoost"}

// dropLocalOnlyKeys removes localOnlyConfigKeys and their children from paths.
func dropLocalOnlyKeys(paths map[string]bool) map[string]bool {
	for p := range paths {
		for _, k := range localOnlyConfigKeys {
			if p == k || strings.HasPrefix(p, k+".") {
				delete(paths, p)
			}
		}
	}
	return paths
}

// TestShippedConfigDocumentsEveryKey fails if a field exists in the config
// structs but is absent from the tracked enode.config.yaml. A missing key is
// silently the Go zero value at load time (a bool becomes false), so a feature an
// operator expects on can quietly turn off — this guards the shipped template
// against a new struct field being added without documenting it.
func TestShippedConfigDocumentsEveryKey(t *testing.T) {
	structPaths := map[string]bool{}
	collectStructPaths(reflect.TypeOf(Config{}), "", structPaths)
	dropLocalOnlyKeys(structPaths)
	shipped := readYAMLKeyPaths(t, shippedConfigPath)

	t.Logf("config struct declares %d key paths", len(structPaths))
	t.Logf("enode.config.yaml carries %d key paths", len(shipped))

	var missing []string
	for p := range structPaths {
		if !shipped[p] {
			missing = append(missing, p)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("enode.config.yaml is missing keys declared in the config structs: %v", missing)
	}
}

// TestConfigFilesHaveMatchingKeys compares the KEY SETS of the two configs —
// never their values. The files intentionally hold different values (dynIp auto
// vs 127.0.0.1, standard vs docker DB ports), so only key presence is checked: a
// key in one file but missing from the other is what silently defaults. Skipped
// when enode.local.yaml is absent (it is gitignored, so not present in CI).
func TestConfigFilesHaveMatchingKeys(t *testing.T) {
	if _, err := os.Stat(localConfigPath); err != nil {
		t.Skipf("skipping cross-file parity: %s not present (%v)", localConfigPath, err)
	}
	shipped := readYAMLKeyPaths(t, shippedConfigPath)
	local := dropLocalOnlyKeys(readYAMLKeyPaths(t, localConfigPath))

	onlyShipped := keysMissingFrom(shipped, local)
	onlyLocal := keysMissingFrom(local, shipped)
	t.Logf("enode.config.yaml keys: %d, enode.local.yaml keys: %d", len(shipped), len(local))
	t.Logf("missing from local.yaml: %v", onlyShipped)
	t.Logf("missing from config.yaml: %v", onlyLocal)

	if len(onlyShipped) > 0 {
		t.Errorf("keys in enode.config.yaml but missing from enode.local.yaml: %v", onlyShipped)
	}
	if len(onlyLocal) > 0 {
		t.Errorf("keys in enode.local.yaml but missing from enode.config.yaml: %v", onlyLocal)
	}
}

// TestShippedConfigOmitsLocalOnlyKeys guards the other direction of the exemption:
// a local-only section must not leak into the published template.
func TestShippedConfigOmitsLocalOnlyKeys(t *testing.T) {
	shipped := readYAMLKeyPaths(t, shippedConfigPath)
	t.Logf("input: %s, local-only keys %v", shippedConfigPath, localOnlyConfigKeys)
	for _, k := range localOnlyConfigKeys {
		t.Logf("output: %s present=%t", k, shipped[k])
		if shipped[k] {
			t.Errorf("enode.config.yaml must not carry the local-only section %q", k)
		}
	}
}

// collectStructPaths walks the config structs by reflection and records every
// yaml key path. Nested config structs are descended into; pointer fields (the
// *bool toggles) are unwrapped; slice/leaf fields stop the recursion so list
// element fields (e.g. ServerEntry.ip) never become top-level keys.
func collectStructPaths(t reflect.Type, prefix string, out map[string]bool) {
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		name := strings.Split(f.Tag.Get("yaml"), ",")[0]
		if name == "" || name == "-" {
			continue
		}
		path := name
		if prefix != "" {
			path = prefix + "." + name
		}
		ft := f.Type
		for ft.Kind() == reflect.Ptr {
			ft = ft.Elem()
		}
		if ft.Kind() == reflect.Struct {
			collectStructPaths(ft, path, out)
			continue
		}
		out[path] = true
	}
}

// readYAMLKeyPaths parses a YAML file and returns the set of dotted key paths it
// contains. Only presence is recorded — values are never inspected. Mappings are
// descended into; scalars and sequences stop (so sequence contents, e.g. list
// entries under `servers`, are never compared).
func readYAMLKeyPaths(t *testing.T, path string) map[string]bool {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var root map[string]any
	if err := yaml.Unmarshal(b, &root); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	out := map[string]bool{}
	collectYAMLPaths(root, "", out)
	return out
}

// keysMissingFrom returns, sorted, the keys present in have but absent from want.
func keysMissingFrom(have, want map[string]bool) []string {
	var missing []string
	for k := range have {
		if !want[k] {
			missing = append(missing, k)
		}
	}
	sort.Strings(missing)
	return missing
}

func collectYAMLPaths(m map[string]any, prefix string, out map[string]bool) {
	for k, v := range m {
		path := k
		if prefix != "" {
			path = prefix + "." + k
		}
		out[path] = true
		if child, ok := v.(map[string]any); ok {
			collectYAMLPaths(child, path, out)
		}
	}
}
