package storage

import (
	"fmt"
	"sync"
	"testing"

	"go.mongodb.org/mongo-driver/v2/bson"
)

// Sizes of the concurrent-offer test: every client offers every file, several times,
// all released at once, so refreshes of one file's counters keep overlapping.
const (
	concurrentClients = 32
	concurrentFiles   = 20
	concurrentRounds  = 6
)

// A files row is shared by every client offering that file, so concurrent offers keep
// recounting the same row. Whatever order those recounts land in, the last one must
// leave the true count: this is the invariant tests/dblatency checks under load, here
// concentrated on few files so an ordering bug has many chances to show.
func TestMySQLConcurrentOffersKeepCountersExact(t *testing.T) {
	requireIntegration(t)
	engine, db := startMySQL(t, "enode_concurrent_offers")
	runConcurrentOffers(t, engine, func(f File) (int64, int64, error) {
		var sources, completed int64
		err := db.QueryRow(`SELECT sources, completed FROM files WHERE hash = ? AND size = ?`, f.Hash, f.Size).
			Scan(&sources, &completed)
		return sources, completed, err
	})
}

// The MongoDB twin of TestMySQLConcurrentOffersKeepCountersExact.
func TestMongoConcurrentOffersKeepCountersExact(t *testing.T) {
	requireIntegration(t)
	engine := startMongoEngine(t, "enode_concurrent_offers")
	runConcurrentOffers(t, engine, func(f File) (int64, int64, error) {
		ctx, cancel := contextWithTimeout(engine)
		defer cancel()
		var doc struct {
			Sources   int64 `bson:"sources"`
			Completed int64 `bson:"completed"`
		}
		err := engine.db.Collection("files").FindOne(ctx, bson.M{"hash": f.Hash, "size": f.Size}).Decode(&doc)
		return doc.Sources, doc.Completed, err
	})
}

// runConcurrentOffers has concurrentClients clients offer the same concurrentFiles
// files concurrentRounds times, flipping each file's complete flag every round, and
// checks the stored counters once all of them are done.
func runConcurrentOffers(t *testing.T, engine Engine, counters func(File) (sources, completed int64, err error)) {
	t.Helper()
	files := make([]File, concurrentFiles)
	for i := range files {
		files[i] = File{Hash: []byte(fmt.Sprintf("concurrent%06d", i)), Size: uint64(5000 + i), Name: fmt.Sprintf("concurrent %d.avi", i)}
	}
	clients := make([]ClientInfo, concurrentClients)
	for i := range clients {
		clients[i] = ClientInfo{ID: uint32(900 + i), IPv4: uint32(0x0a000001 + i), Port: 4662, Hash: []byte(fmt.Sprintf("concurrentclie%02d", i))}
		id, err := engine.Connect(clients[i])
		if err != nil {
			t.Fatal(err)
		}
		clients[i].StoreID = id
	}

	// Client c marks every file complete in round r when (c + r) is odd, so after the
	// last round exactly half of the clients have it complete.
	wantCompleted := int64(0)
	for c := range clients {
		if (c+concurrentRounds-1)%2 == 1 {
			wantCompleted++
		}
	}
	t.Logf("input: %d clients x %d rounds offering the same %d files concurrently; want sources=%d completed=%d",
		concurrentClients, concurrentRounds, concurrentFiles, concurrentClients, wantCompleted)

	start := make(chan struct{})
	var wg sync.WaitGroup
	for c, client := range clients {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for r := 0; r < concurrentRounds; r++ {
				offer := append([]File(nil), files...)
				for i := range offer {
					offer[i].Completed = uint32((c + r) % 2)
				}
				engine.AddFiles(offer, client)
			}
		}()
	}
	close(start)
	wg.Wait()

	wrong := 0
	for _, f := range files {
		sources, completed, err := counters(f)
		if err != nil {
			t.Fatalf("read %s: %v", f.Hash, err)
		}
		if sources != concurrentClients || completed != wantCompleted {
			wrong++
			t.Errorf("%s: sources=%d completed=%d, want %d/%d", f.Hash, sources, completed, concurrentClients, wantCompleted)
		}
	}
	t.Logf("output: %d of %d files have exact counters", concurrentFiles-wrong, concurrentFiles)
}
