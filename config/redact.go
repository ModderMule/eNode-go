package config

import (
	"reflect"
	"strings"

	"gopkg.in/yaml.v3"
)

// RedactedMark replaces a secret that is set. An unset secret stays empty, so the
// view still tells "no password" from "a password".
const RedactedMark = "(set, hidden)"

// secretKeys are the key paths whose values must never leave the process: credentials,
// tokens, key seeds, and the addresses of the databases they open. A path covers
// itself and, for a list, the key in every entry (serverSearch.peers.token).
// TestRedactedCoversSecretLookingKeys fails when a key that reads like a secret is on
// neither this list nor publicKeys.
var secretKeys = []string{
	"admin.username",
	"admin.password",
	"udp.serverKey",
	"filter.geoip.accountID",
	"filter.geoip.licenseKey",
	"metaSearch.torrent.token",
	"metaSearch.usenet.token",
	"metaSearch.kad.token",
	"metaSearch.web.token",
	"metaApi.tls.keyFile",
	"serverSearch.tls.keyFile",
	"serverSearch.peers.token",
	"storage.mysql.host",
	"storage.mysql.user",
	"storage.mysql.pass",
	"storage.mongodb.host",
	"storage.mongodb.uri",
	"storage.manticore.dsn",
}

// publicKeys read like secrets and are not: a word list, a public key, a length.
var publicKeys = []string{
	"filter.keywords",
	"filter.keywordBanThreshold",
	"filter.update.publicKey",
	"metaApi.accounts.minPasswordLength",
}

// omittedKeys are left out of the view altogether. statsBoost is local-only config
// that says how far the advertised counts are inflated.
var omittedKeys = []string{"statsBoost"}

// RedactedYAML renders cfg as YAML with every secret replaced by RedactedMark. A
// registration step keeps its id, type and enabled flag only: the rest of the entry
// is the step type's own configuration, which for a payment step is API credentials.
func RedactedYAML(cfg Config) ([]byte, error) {
	node, err := redactValue(reflect.ValueOf(cfg), "")
	if err != nil {
		return nil, err
	}
	return yaml.Marshal(node)
}

// redactValue builds the YAML node for v, the value at path.
func redactValue(v reflect.Value, path string) (*yaml.Node, error) {
	if isSecretPath(path) {
		return redactedLeaf(v), nil
	}
	switch {
	case v.Type() == reflect.TypeOf([]AccountStepConfig(nil)):
		return redactSteps(v.Interface().([]AccountStepConfig)), nil
	case v.Kind() == reflect.Struct && v.Type() != reflect.TypeOf(yaml.Node{}):
		return redactStruct(v, path)
	case v.Kind() == reflect.Slice && v.Type().Elem().Kind() == reflect.Struct:
		seq := &yaml.Node{Kind: yaml.SequenceNode}
		for i := 0; i < v.Len(); i++ {
			// A list entry has the list's own path, so serverSearch.peers.token
			// names the token of every peer.
			item, err := redactValue(v.Index(i), path)
			if err != nil {
				return nil, err
			}
			seq.Content = append(seq.Content, item)
		}
		return seq, nil
	}
	node := &yaml.Node{}
	if err := node.Encode(v.Interface()); err != nil {
		return nil, err
	}
	return node, nil
}

func redactStruct(v reflect.Value, path string) (*yaml.Node, error) {
	m := &yaml.Node{Kind: yaml.MappingNode}
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		name := yamlFieldName(f)
		if name == "-" {
			continue
		}
		child := name
		if path != "" {
			child = path + "." + name
		}
		if isOmittedPath(child) {
			continue
		}
		value, err := redactValue(v.Field(i), child)
		if err != nil {
			return nil, err
		}
		m.Content = append(m.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: name}, value)
	}
	return m, nil
}

// redactSteps keeps what identifies a registration step and drops its settings.
func redactSteps(steps []AccountStepConfig) *yaml.Node {
	seq := &yaml.Node{Kind: yaml.SequenceNode}
	for _, s := range steps {
		entry := &yaml.Node{}
		_ = entry.Encode(map[string]any{"id": s.ID, "type": s.Type, "enabled": s.Enabled, "settings": RedactedMark})
		seq.Content = append(seq.Content, entry)
	}
	return seq
}

// redactedLeaf hides a secret that is set and shows an unset one as empty.
func redactedLeaf(v reflect.Value) *yaml.Node {
	for v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: ""}
		}
		v = v.Elem()
	}
	if v.IsZero() {
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: ""}
	}
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: RedactedMark}
}

func yamlFieldName(f reflect.StructField) string {
	name := strings.Split(f.Tag.Get("yaml"), ",")[0]
	if name == "" {
		name = strings.ToLower(f.Name)
	}
	return name
}

func isSecretPath(path string) bool  { return containsPath(secretKeys, path) }
func isOmittedPath(path string) bool { return containsPath(omittedKeys, path) }

func containsPath(list []string, path string) bool {
	for _, k := range list {
		if k == path {
			return true
		}
	}
	return false
}
