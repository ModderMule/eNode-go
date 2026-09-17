package dblatency

import (
	"database/sql"
	"testing"
	"time"

	"enode/storage"
)

// TestMySQLRoundTrips measures the mysql engine against MariaDB 10.11, the dialect the
// server defaults to.
func TestMySQLRoundTrips(t *testing.T) {
	engine, proxy, direct := startMariaDB(t)

	t.Logf("input: mariadb:10.11 behind a counting proxy, storage.MySQLEngine defaults (interpolateParams on)")
	t.Logf("output: round-trips per storage.Engine call")
	b := &bench{t: t, proxy: proxy}

	var err error
	a := storage.ClientInfo{ID: 0x0100007f, IPv4: 0x0100007f, Port: 4662, Hash: benchHash('A', 0)}
	if a.StoreID, err = engine.Connect(a); err != nil {
		t.Fatal(err)
	}
	other := storage.ClientInfo{ID: 0x0200007f, IPv4: 0x0200007f, Port: 4662, Hash: benchHash('B', 0)}
	offer := benchFiles('o', 0, packetFiles)

	b.measure("IsConnected", func() { engine.IsConnected(storage.ClientInfo{Hash: a.Hash}) })
	b.measure("Connect (login)", func() { other.StoreID, _ = engine.Connect(other) })
	addFile := b.measure("AddFile, new file", func() { engine.AddFile(benchFiles('s', 0, 1)[0], a) })
	b.measure("AddFile, same file again", func() { engine.AddFile(benchFiles('s', 0, 1)[0], a) })
	addFiles := b.measure("AddFiles, 200 new files", func() { engine.AddFiles(offer, a) })
	b.measure("AddFiles, same 200 again", func() { engine.AddFiles(offer, a) })
	b.measure("GetSources", func() { engine.GetSources(offer[0].Hash, offer[0].Size) })
	b.measure("GetSourcesByHash", func() { engine.GetSourcesByHash(offer[0].Hash) })
	b.measure("FindBySearch, 1 term", func() {
		engine.FindBySearch(&storage.SearchExpr{Kind: storage.SearchText, Text: "benchmark"})
	})
	b.measure("ClientsCount", func() { engine.ClientsCount() })
	b.measure("FilesCount", func() { engine.FilesCount() })
	b.measure("Disconnect", func() { engine.Disconnect(other) })
	measureLargeReads(t, b, engine)
	sweep10 := measureMySQLSweep(t, b, engine, direct, 'c', 10)
	sweep100 := measureMySQLSweep(t, b, engine, direct, 'd', 100)
	sweep1000 := measureMySQLSweep(t, b, engine, direct, 'e', 1000)

	if addFile.roundTrips > 4 {
		t.Errorf("AddFile took %d round-trips, want at most 4 — is interpolateParams off?", addFile.roundTrips)
	}
	if addFiles.roundTrips > 4 {
		t.Errorf("AddFiles(%d) took %d round-trips, want at most 4 — the offer is not batched", packetFiles, addFiles.roundTrips)
	}
	assertSweepFlat(t, sweep10, sweep100, sweep1000)

	compareOfferPaths(t, proxy, engine, a)
}

// measureMySQLSweep leaves n files whose only source is a stale offline client, then
// measures the sweep that removes it.
func measureMySQLSweep(t *testing.T, b *bench, engine *storage.MySQLEngine, direct *sql.DB, prefix byte, n int) proxyCounts {
	t.Helper()
	stale := storage.ClientInfo{ID: uint32(prefix), IPv4: 0x0300007f, Port: 4662, Hash: benchHash(prefix, 1<<40)}
	var err error
	if stale.StoreID, err = engine.Connect(stale); err != nil {
		t.Fatal(err)
	}
	engine.AddFiles(benchFiles(prefix, 0, n), stale)
	engine.Disconnect(stale)
	if _, err := direct.Exec(`UPDATE clients SET time_login = NOW() - INTERVAL 48 HOUR WHERE id = ?`, stale.StoreID); err != nil {
		t.Fatal(err)
	}
	if _, err := direct.Exec(`UPDATE sources SET time_offer = NOW() - INTERVAL 48 HOUR WHERE id_client = ?`, stale.StoreID); err != nil {
		t.Fatal(err)
	}
	var result storage.CleanupResult
	counts := b.measure(labelSweep(n), func() {
		result, err = engine.CleanupStale(24*time.Hour, storage.CleanupOptions{KeepZeroSourceFiles: true})
	})
	if err != nil || result.Clients != 1 {
		t.Fatalf("sweep of %d files: result=%+v err=%v", n, result, err)
	}
	return counts
}
