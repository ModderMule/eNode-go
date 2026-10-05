package config

import (
	"bytes"
	"reflect"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Support for reloading the config file while the server runs. Diff says which keys
// differ between two configs, Reloadable says whether a key can be applied without a
// restart, and OverlayReloadable builds the config a reload actually applies.

// reloadableKeys are the key paths a running server can apply. An entry covers the key
// itself and everything beneath it. OverlayReloadable copies exactly these keys;
// TestOverlayMatchesReloadableKeys fails if the two drift apart.
var reloadableKeys = []string{
	"name",
	"description",
	"messageLowID",
	"messageLogin",
	"logLevel",
	"logFile",
	"servers",
	"tcp.connectionTimeout",
	"tcp.disconnectTimeout",
	"tcp.loginTimeout",
	"tcp.maxConnectionsPerIP",
	"udp.getSources",
	"udp.getFiles",
	"files",
	"admin.username",
	"admin.password",
	"gossip",
	"statsBoost",
}

// Diff returns the sorted key paths whose values differ between a and b, in the dotted
// form the YAML file uses (tcp.loginTimeout). A list is one key: any change inside it
// reports the list's own path. Only paths are returned, never values, so the result is
// safe to log and to show in the admin UI even when a password or token changed.
func Diff(a, b Config) []string {
	var out []string
	diffValue(reflect.ValueOf(a), reflect.ValueOf(b), "", &out)
	sort.Strings(out)
	return out
}

// Reloadable reports whether a change to the key at path is applied by a config reload.
// Every other key takes effect only after a restart.
func Reloadable(path string) bool {
	for _, k := range reloadableKeys {
		if path == k || strings.HasPrefix(path, k+".") {
			return true
		}
	}
	return false
}

// OverlayReloadable returns base with every reloadable key taken from next. A reload
// applies this rather than next itself, so a key that needs a restart keeps the value
// the process started with and can never reach a live subsystem half-applied.
func OverlayReloadable(base, next Config) Config {
	out := base
	out.Name = next.Name
	out.Description = next.Description
	out.MessageLowID = next.MessageLowID
	out.MessageLogin = next.MessageLogin
	out.LogLevel = next.LogLevel
	out.LogFile = next.LogFile
	out.Servers = next.Servers
	out.TCP.ConnectionTimeout = next.TCP.ConnectionTimeout
	out.TCP.DisconnectTimeout = next.TCP.DisconnectTimeout
	out.TCP.LoginTimeout = next.TCP.LoginTimeout
	out.TCP.MaxConnectionsPerIP = next.TCP.MaxConnectionsPerIP
	out.UDP.GetSources = next.UDP.GetSources
	out.UDP.GetFiles = next.UDP.GetFiles
	out.Files = next.Files
	out.Admin.Username = next.Admin.Username
	out.Admin.Password = next.Admin.Password
	out.Gossip = next.Gossip
	out.StatsBoost = next.StatsBoost
	return out
}

// diffValue walks two values of the same struct type and appends the path of every
// differing leaf. Structs are descended into by yaml tag; everything else is a leaf.
func diffValue(a, b reflect.Value, prefix string, out *[]string) {
	if a.Kind() != reflect.Struct || a.Type() == reflect.TypeOf(yaml.Node{}) {
		if !leafEqual(a, b) {
			*out = append(*out, prefix)
		}
		return
	}
	t := a.Type()
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		name := strings.Split(f.Tag.Get("yaml"), ",")[0]
		if name == "-" {
			continue
		}
		if name == "" {
			name = strings.ToLower(f.Name)
		}
		path := name
		if prefix != "" {
			path = prefix + "." + name
		}
		diffValue(a.Field(i), b.Field(i), path, out)
	}
}

// leafEqual compares two leaves by their YAML encoding. That treats a pointer and the
// value it points to alike, and ignores the line and column a raw yaml.Node carries, so
// moving an entry within the file is not reported as a change.
func leafEqual(a, b reflect.Value) bool {
	ya, errA := yaml.Marshal(a.Interface())
	yb, errB := yaml.Marshal(b.Interface())
	if errA != nil || errB != nil {
		return reflect.DeepEqual(a.Interface(), b.Interface())
	}
	return bytes.Equal(ya, yb)
}
