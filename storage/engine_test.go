package storage

import (
	"testing"

	mysqldriver "github.com/go-sql-driver/mysql"
)

func TestEngineConstructorsValidateConfig(t *testing.T) {
	if _, err := NewMySQLEngine(MySQLConfig{}); err == nil {
		t.Fatalf("expected mysql config error")
	}
	if _, err := NewMongoDBEngine(MongoConfig{}); err == nil {
		t.Fatalf("expected mongodb config error")
	}
}

// Without interpolateParams every parameterised statement is a PREPARE round-trip
// followed by an EXECUTE round-trip, which doubled the cost of every hot-path call
// against a remote database. ParseDSN is also where the driver refuses interpolation
// under an unsafe collation, so a parse error here would mean the flag and the
// charset cannot coexist.
func TestMySQLDSNInterpolatesParams(t *testing.T) {
	engine, err := NewMySQLEngine(MySQLConfig{
		Host: "db.example", Port: 3306, User: "enode", Pass: "secret", Database: "enode",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("input: host=db.example port=3306 user=enode database=enode")

	cfg, err := mysqldriver.ParseDSN(engine.dsn())
	if err != nil {
		t.Fatalf("driver rejected the DSN: %v", err)
	}
	t.Logf("output: interpolateParams=%t collation=%s parseTime=%t addr=%s",
		cfg.InterpolateParams, cfg.Collation, cfg.ParseTime, cfg.Addr)

	if !cfg.InterpolateParams {
		t.Fatal("interpolateParams is off: every statement pays a COM_STMT_PREPARE round-trip")
	}
	if cfg.Collation != "utf8mb4_unicode_ci" || !cfg.ParseTime {
		t.Fatalf("collation=%q parseTime=%t, want utf8mb4_unicode_ci and true", cfg.Collation, cfg.ParseTime)
	}
}
