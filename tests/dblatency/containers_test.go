package dblatency

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"testing"
	"time"

	"enode/storage"
	"enode/tests"

	_ "github.com/go-sql-driver/mysql"
	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// startMariaDB runs MariaDB 10.11, the dialect the server defaults to, and returns an
// engine that reaches it through a counting proxy, the proxy, and a direct connection
// for test-side reads and writes that must never show in a count.
func startMariaDB(t *testing.T) (*storage.MySQLEngine, *rttProxy, *sql.DB) {
	t.Helper()
	pool := requireIntegration(t)
	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository: "mariadb",
		Tag:        "10.11",
		Env:        []string{"MARIADB_ROOT_PASSWORD=root", "MARIADB_DATABASE=enode"},
	}, func(hc *docker.HostConfig) {
		hc.AutoRemove = true
		hc.RestartPolicy = docker.RestartPolicy{Name: "no"}
	})
	if err != nil {
		t.Fatalf("start mariadb: %v", err)
	}
	t.Cleanup(func() { _ = pool.Purge(resource) })

	backend := "127.0.0.1:" + resource.GetPort("3306/tcp")
	proxy := startProxy(t, backend, mysqlFrames{})
	host, port, _ := net.SplitHostPort(proxy.addr())
	engine, err := storage.NewMySQLEngine(storage.MySQLConfig{
		Host: host, Port: mustAtoi(t, port), User: "root", Pass: "root", Database: "enode",
		// storage.mysql.connections defaults to 8.
		MaxOpenConns: 8, MaxIdleConns: 8,
		SchemaFile: tests.FixRelativeTestingPath("misc/enode.sql"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := pool.Retry(engine.Init); err != nil {
		t.Fatalf("mariadb not ready: %v", err)
	}
	t.Cleanup(func() { _ = engine.Close() })

	direct, err := sql.Open("mysql", "root:root@tcp("+backend+")/enode?parseTime=true")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = direct.Close() })
	return engine, proxy, direct
}

// startMongo runs MongoDB 7 and returns an engine behind a counting proxy, the proxy,
// and a direct handle on the engine's database.
func startMongo(t *testing.T, database string) (*storage.MongoDBEngine, *rttProxy, *mongo.Database) {
	t.Helper()
	pool := requireIntegration(t)
	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository: "mongo",
		Tag:        "7",
	}, func(hc *docker.HostConfig) {
		hc.AutoRemove = true
		hc.RestartPolicy = docker.RestartPolicy{Name: "no"}
	})
	if err != nil {
		t.Fatalf("start mongo: %v", err)
	}
	t.Cleanup(func() { _ = pool.Purge(resource) })

	backend := "127.0.0.1:" + resource.GetPort("27017/tcp")
	proxy := startProxy(t, backend, mongoFrames{})
	engine, err := storage.NewMongoDBEngine(storage.MongoConfig{
		// directConnection keeps the driver on the proxy's address rather than
		// whatever address the server reports for itself.
		URI:      fmt.Sprintf("mongodb://%s/?directConnection=true", proxy.addr()),
		Database: database,
		Timeout:  30 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := pool.Retry(engine.Init); err != nil {
		t.Fatalf("mongo not ready: %v", err)
	}
	t.Cleanup(func() { _ = engine.Close() })

	direct, err := mongo.Connect(options.Client().ApplyURI(fmt.Sprintf("mongodb://%s/?directConnection=true", backend)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = direct.Disconnect(context.Background()) })
	return engine, proxy, direct.Database(database)
}
