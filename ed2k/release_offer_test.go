package ed2k

import (
	"testing"

	"enode/storage"
)

// offerCountingEngine counts AddFiles calls that reach storage.
type offerCountingEngine struct {
	*storage.MemoryEngine
	adds int
}

func (e *offerCountingEngine) AddFiles(files []storage.File, info storage.ClientInfo) {
	e.adds++
	e.MemoryEngine.AddFiles(files, info)
}

// A same-IP re-login releases the old session from the new one's goroutine while
// the old one may still be handling an OP_OFFERFILES. Its AddFiles then landed after
// Disconnect: orphaned sources on the memory engine, and on MySQL/Mongo, whose rows
// are keyed by hash, the old offer attached to the new session.
func TestOfferAfterReleaseIsNotStored(t *testing.T) {
	engine := &offerCountingEngine{MemoryEngine: storage.NewMemoryEngine()}
	rt := NewServerRuntime(TCPRuntimeConfig{Address: "127.0.0.1", Port: 4661}, UDPRuntimeConfig{}, engine)
	c := newTCPClient(rt, &mockConn{}, false)
	c.infoMu.Lock()
	c.logged = true
	c.info.Hash = []byte("released-session")
	c.info.StoreID, _ = engine.Connect(c.info)
	c.infoMu.Unlock()

	batch := []storage.File{{Hash: []byte("released-file-01"), Name: "r.iso", Size: 1}}
	c.addFiles(batch, c.snapshotInfo())
	c.releaseSession()
	c.addFiles(batch, c.snapshotInfo())
	t.Logf("input: one offer before release, one after; output: AddFiles reached storage %d time(s)", engine.adds)
	if engine.adds != 1 {
		t.Fatalf("want 1 AddFiles, got %d", engine.adds)
	}
}
