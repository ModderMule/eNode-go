package storage

import (
	"database/sql"
	"fmt"
	"testing"
	"time"

	"enode/tests"

	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
)

// The AccountStore conformance suite (accounts_test.go) on the database engines.
// Run with ENODE_INTEGRATION=1 and Docker.

func TestMySQLAccountStore(t *testing.T) {
	requireIntegration(t)
	engine, _ := startMySQL(t, "enode")
	testAccountStore(t, engine)
}

// TestMariaDBAccountStore covers the default dialect: the account DDL must not use
// anything MySQL-only.
func TestMariaDBAccountStore(t *testing.T) {
	requireIntegration(t)
	pool, err := dockertest.NewPool("")
	if err != nil {
		t.Skipf("docker not available: %v", err)
	}
	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository: "mariadb",
		Tag:        "11",
		Env:        []string{"MARIADB_ROOT_PASSWORD=root", "MARIADB_DATABASE=enode"},
	}, func(hc *docker.HostConfig) {
		hc.AutoRemove = true
		hc.RestartPolicy = docker.RestartPolicy{Name: "no"}
	})
	if err != nil {
		t.Fatalf("start mariadb container: %v", err)
	}
	t.Cleanup(func() { _ = pool.Purge(resource) })
	port := resource.GetPort("3306/tcp")
	pool.MaxWait = 2 * time.Minute
	if err := pool.Retry(func() error {
		db, err := sql.Open("mysql", fmt.Sprintf("root:root@tcp(localhost:%s)/enode", port))
		if err != nil {
			return err
		}
		defer db.Close()
		return db.Ping()
	}); err != nil {
		t.Fatalf("mariadb not ready: %v", err)
	}
	engine, err := NewMySQLEngine(MySQLConfig{
		Host: "localhost", Port: mustAtoi(port), User: "root", Pass: "root", Database: "enode",
		MaxOpenConns: 4, MaxIdleConns: 2, Dialect: DialectMariaDB,
		SchemaFile: tests.FixRelativeTestingPath("misc/enode.sql"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.Init(); err != nil {
		t.Fatalf("init: %v", err)
	}
	t.Cleanup(func() { _ = engine.Close() })
	testAccountStore(t, engine)
}

func TestMongoAccountStore(t *testing.T) {
	requireIntegration(t)
	testAccountStore(t, startMongoEngine(t, "enode_accounts"))
}
