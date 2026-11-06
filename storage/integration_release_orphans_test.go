package storage

import (
	"bytes"
	"testing"
)

// releaseOrphansFixture connects keep and gone, each offering one file, and returns
// the file hashes in the same order.
func releaseOrphansFixture(t *testing.T, engine Engine, keep, gone []byte) (keepFile, goneFile []byte) {
	t.Helper()
	keepFile, goneFile = bytes.Repeat([]byte{0x61}, 16), bytes.Repeat([]byte{0x62}, 16)
	for i, h := range [][]byte{keep, gone} {
		c := ClientInfo{Hash: h, ID: uint32(0x0a000001 + i), IPv4: uint32(0x0a000001 + i), Port: uint16(4662 + i)}
		id, err := engine.Connect(c)
		if err != nil {
			t.Fatal(err)
		}
		c.StoreID = id
		file := keepFile
		if i == 1 {
			file = goneFile
		}
		engine.AddFile(File{Hash: file, Size: 1024, Name: "orphan.bin", Type: "Archive"}, c)
	}
	return keepFile, goneFile
}

func assertReleaseOrphans(t *testing.T, engine Engine) {
	t.Helper()
	keep, gone := bytes.Repeat([]byte{0x41}, 16), bytes.Repeat([]byte{0x42}, 16)
	keepFile, goneFile := releaseOrphansFixture(t, engine, keep, gone)

	released, err := engine.ReleaseOrphans(func(h []byte) bool { return bytes.Equal(h, keep) })
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("output: released=%x", released)
	if len(released) != 1 || !bytes.Equal(released[0], gone) {
		t.Fatalf("released=%x want [%x]", released, gone)
	}
	if !engine.IsConnected(ClientInfo{Hash: keep}) {
		t.Fatal("held client released")
	}
	if engine.IsConnected(ClientInfo{Hash: gone}) {
		t.Fatal("orphan still online")
	}
	if n := len(engine.GetSourcesByHash(goneFile)); n != 0 {
		t.Fatalf("orphan still listed as a source (%d)", n)
	}
	if n := len(engine.GetSourcesByHash(keepFile)); n != 1 {
		t.Fatalf("held client's source count=%d want 1", n)
	}
}

// Disconnect with no StoreID, as a login releasing an orphaned row calls it.
func assertDisconnectByHash(t *testing.T, engine Engine) {
	t.Helper()
	h := bytes.Repeat([]byte{0x43}, 16)
	if _, err := engine.Connect(ClientInfo{Hash: h, ID: 0x0a000009, IPv4: 0x0a000009, Port: 4670}); err != nil {
		t.Fatal(err)
	}
	engine.Disconnect(ClientInfo{Hash: h})
	if engine.IsConnected(ClientInfo{Hash: h}) {
		t.Fatal("disconnect by hash left the client online")
	}
}

func TestMySQLReleaseOrphans(t *testing.T) {
	requireIntegration(t)
	engine, _ := startMySQL(t, "enode")
	assertReleaseOrphans(t, engine)
	assertDisconnectByHash(t, engine)
}

func TestMongoReleaseOrphans(t *testing.T) {
	requireIntegration(t)
	engine := startMongoEngine(t, "enode_release_orphans")
	assertReleaseOrphans(t, engine)
	assertDisconnectByHash(t, engine)
}
