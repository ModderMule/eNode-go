package config

import (
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestRedactedYAMLHidesSecrets(t *testing.T) {
	var cfg Config
	cfg.Name = "visible name"
	cfg.Admin.Username = "operator-user"
	cfg.Admin.Password = "operator-pass"
	cfg.UDP.ServerKey = 3141592653
	cfg.Filter.GeoIP.AccountID = "geo-account"
	cfg.Filter.GeoIP.LicenseKey = "geo-license"
	cfg.Filter.Keywords = "visible|words"
	cfg.MetaSearch.Torrent.Token = "torrent-token"
	cfg.MetaSearch.Web.Token = "web-token"
	cfg.MetaAPI.TLS.KeyFile = "/secret/meta.key"
	cfg.ServerSearch.TLS.KeyFile = "/secret/search.key"
	cfg.ServerSearch.Peers = []ServerSearchPeer{{URL: "https://peer.example", Token: "peer-token"}}
	cfg.Storage.MySQL.Host = "db.internal"
	cfg.Storage.MySQL.User = "db-user"
	cfg.Storage.MySQL.Pass = "db-pass"
	cfg.Storage.MongoDB.URI = "mongodb://u:p@mongo.internal"
	cfg.StatsBoost.Users = 987654
	var step AccountStepConfig
	if err := yaml.Unmarshal([]byte("id: pay\ntype: payment\nenabled: true\napiSecret: step-secret\n"), &step); err != nil {
		t.Fatalf("step fixture: %v", err)
	}
	cfg.MetaAPI.Accounts.Steps = []AccountStepConfig{step}

	out, err := RedactedYAML(cfg)
	if err != nil {
		t.Fatalf("RedactedYAML: %v", err)
	}
	text := string(out)
	t.Logf("input: a config with every secret set")
	t.Logf("output:\n%s", text)

	for _, secret := range []string{
		"operator-user", "operator-pass", "3141592653", "geo-account", "geo-license",
		"torrent-token", "web-token", "/secret/meta.key", "/secret/search.key", "peer-token",
		"db.internal", "db-user", "db-pass", "mongo.internal", "987654", "step-secret", "statsBoost",
	} {
		if strings.Contains(text, secret) {
			t.Errorf("redacted config still contains %q", secret)
		}
	}
	for _, visible := range []string{"visible name", "visible|words", "https://peer.example", "id: pay", "type: payment"} {
		if !strings.Contains(text, visible) {
			t.Errorf("redacted config lost %q", visible)
		}
	}
}

func TestRedactedYAMLShowsUnsetSecretsAsEmpty(t *testing.T) {
	out, err := RedactedYAML(Config{})
	if err != nil {
		t.Fatalf("RedactedYAML: %v", err)
	}
	t.Logf("input: the zero config")
	t.Logf("output: %d bytes, contains the mark: %t", len(out), strings.Contains(string(out), RedactedMark))
	if strings.Contains(string(out), RedactedMark) {
		t.Fatalf("an unset secret was rendered as set")
	}
}

// TestRedactedCoversSecretLookingKeys fails when a config key that reads like a secret
// is listed neither as secret nor as public, so a new credential cannot reach the admin
// UI by being forgotten.
func TestRedactedCoversSecretLookingKeys(t *testing.T) {
	looksSecret := regexp.MustCompile(`(?i)(pass|token|secret|key|uri|license|credential)`)
	paths := map[string]bool{}
	collectRedactPaths(reflect.TypeOf(Config{}), "", paths)

	var unlisted []string
	for p := range paths {
		leaf := p[strings.LastIndex(p, ".")+1:]
		if !looksSecret.MatchString(leaf) {
			continue
		}
		if !containsPath(secretKeys, p) && !containsPath(publicKeys, p) {
			unlisted = append(unlisted, p)
		}
	}
	sort.Strings(unlisted)
	t.Logf("input: %d config key paths", len(paths))
	t.Logf("output: secret-looking keys on neither list: %v", unlisted)
	if len(unlisted) > 0 {
		t.Fatalf("add these to secretKeys or publicKeys in redact.go: %v", unlisted)
	}
	for _, k := range append(append([]string{}, secretKeys...), publicKeys...) {
		if !paths[k] {
			t.Errorf("redact.go lists %q, which is not a config key", k)
		}
	}
}

// collectRedactPaths lists every key path RedactedYAML can meet, descending into
// structs and lists of structs the way redactValue does.
func collectRedactPaths(t reflect.Type, prefix string, out map[string]bool) {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Kind() == reflect.Slice && t.Elem().Kind() == reflect.Struct && t != reflect.TypeOf([]AccountStepConfig(nil)) {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct || t == reflect.TypeOf(yaml.Node{}) {
		return
	}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		name := yamlFieldName(f)
		if name == "-" {
			continue
		}
		path := name
		if prefix != "" {
			path = prefix + "." + name
		}
		out[path] = true
		collectRedactPaths(f.Type, path, out)
	}
}
