package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfigYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "enode.config.yaml")
	err := os.WriteFile(path, []byte(`
address: 127.0.0.1
supportCrypt: true
tcp:
  port: 5555
udp:
  port: 5559
storage:
  engine: mysql
  mysql:
    host: localhost
    port: 3306
    user: enode
    pass: password
    database: enode
`), 0o644)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TCP.Port != 5555 || cfg.UDP.Port != 5559 {
		t.Fatalf("bad ports: %+v", cfg)
	}
	if cfg.LogLevel != "info" || cfg.LogFile != "logs/enode.log" {
		t.Fatalf("bad log defaults: level=%q file=%q", cfg.LogLevel, cfg.LogFile)
	}
	if len(cfg.TestURLs) == 0 {
		t.Fatalf("bad testUrls defaults: %+v", cfg.TestURLs)
	}
	if cfg.NAT.Port != 2004 || cfg.NAT.RegistrationTTLSeconds != 90 {
		t.Fatalf("bad nat defaults: %+v", cfg.NAT)
	}
	s := cfg.StorageEngineConfig()
	if s.Engine != "mysql" || s.MySQL.Database != "enode" {
		t.Fatalf("bad storage config: %+v", s)
	}
}
