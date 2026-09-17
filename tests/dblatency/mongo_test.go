package dblatency

import (
	"context"
	"testing"
	"time"

	"enode/storage"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

// TestMongoRoundTrips measures the mongodb engine against MongoDB 7.
func TestMongoRoundTrips(t *testing.T) {
	engine, proxy, db := startMongo(t, "enode_bench")

	t.Logf("input: mongo:7 behind a counting proxy, storage.MongoDBEngine defaults")
	t.Logf("output: round-trips per storage.Engine call (driver handshakes and heartbeats excluded)")
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
	b.measure("AddFile, new file", func() { engine.AddFile(benchFiles('s', 0, 1)[0], a) })
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
	large := measureLargeReads(t, b, engine)
	sweep10 := measureMongoSweep(t, b, engine, db, 'c', 10)
	sweep100 := measureMongoSweep(t, b, engine, db, 'd', 100)
	sweep1000 := measureMongoSweep(t, b, engine, db, 'e', 1000)

	if addFiles.roundTrips > 4 {
		t.Errorf("AddFiles(%d) took %d round-trips, want at most 4 — the offer is not batched", packetFiles, addFiles.roundTrips)
	}
	if large.getSources.roundTrips != 1 {
		t.Errorf("GetSources over %d sources took %d round-trips, want 1 — the cursor needed a getMore",
			crowdSources, large.getSources.roundTrips)
	}
	if large.search.roundTrips != 1 {
		t.Errorf("FindBySearch returning %d files took %d round-trips, want 1 — the cursor needed a getMore",
			storage.MaxSearchResults, large.search.roundTrips)
	}
	assertSweepFlat(t, sweep10, sweep100, sweep1000)

	compareOfferPaths(t, proxy, engine, a)
}

// measureMongoSweep leaves n files whose only source is a stale offline client, then
// measures the sweep that removes it.
func measureMongoSweep(t *testing.T, b *bench, engine *storage.MongoDBEngine, db *mongo.Database, prefix byte, n int) proxyCounts {
	t.Helper()
	stale := storage.ClientInfo{ID: uint32(prefix), IPv4: 0x0300007f, Port: 4662, Hash: benchHash(prefix, 1<<40)}
	if _, err := engine.Connect(stale); err != nil {
		t.Fatal(err)
	}
	engine.AddFiles(benchFiles(prefix, 0, n), stale)
	engine.Disconnect(stale)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	old := time.Now().Add(-48 * time.Hour)
	if _, err := db.Collection("clients").UpdateOne(ctx, bson.M{"hash": stale.Hash},
		bson.M{"$set": bson.M{"time_login": old}}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Collection("sources").UpdateMany(ctx, bson.M{"client_hash": stale.Hash},
		bson.M{"$set": bson.M{"time_offer": old}}); err != nil {
		t.Fatal(err)
	}

	var result storage.CleanupResult
	var err error
	counts := b.measure(labelSweep(n), func() {
		result, err = engine.CleanupStale(24*time.Hour, storage.CleanupOptions{KeepZeroSourceFiles: true})
	})
	if err != nil || result.Clients != 1 {
		t.Fatalf("sweep of %d files: result=%+v err=%v", n, result, err)
	}
	return counts
}
