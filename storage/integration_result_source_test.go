package storage

import (
	"testing"
)

// resultSourceAfterDisconnect publishes one file from two clients, disconnects the
// later one (whose id/port the file carries) and returns the search result's source.
func resultSourceAfterDisconnect(t *testing.T, engine Engine) (before, after File) {
	t.Helper()
	a := ClientInfo{ID: 0x0a000001, IPv4: 0x0100000a, Port: 4662, Hash: []byte("result-src-a-001")}
	b := ClientInfo{ID: 0x0b000001, IPv4: 0x0100000b, Port: 4663, Hash: []byte("result-src-b-001")}
	var err error
	if a.StoreID, err = engine.Connect(a); err != nil {
		t.Fatal(err)
	}
	if b.StoreID, err = engine.Connect(b); err != nil {
		t.Fatal(err)
	}
	file := File{Hash: []byte("result-source-01"), Name: "resultsource.iso", Size: 10, Type: "Pro"}
	engine.AddFile(file, a)
	engine.AddFile(file, b)

	find := func() File {
		got := engine.FindBySearch(&SearchExpr{Kind: SearchText, Text: "resultsource"})
		if len(got) != 1 {
			t.Fatalf("want 1 result, got %d", len(got))
		}
		return got[0]
	}
	before = find()
	engine.Disconnect(b)
	return before, find()
}

// files.source_id/source_port name one source in every search result. They were the
// last offerer's and stayed after it left, when its LowID could already be someone
// else's; the disconnecting client's own pair is cleared.
func TestMySQLDisconnectClearsResultSource(t *testing.T) {
	requireIntegration(t)
	engine, _ := startMySQL(t, "enode")
	before, after := resultSourceAfterDisconnect(t, engine)
	t.Logf("input: last offerer disconnects, output: result source %#x:%d → %#x:%d",
		before.SourceID, before.SourcePort, after.SourceID, after.SourcePort)
	if before.SourceID != 0x0b000001 || after.SourceID != 0 || after.SourcePort != 0 {
		t.Fatalf("want 0x0b000001 then 0, got %#x then %#x:%d", before.SourceID, after.SourceID, after.SourcePort)
	}
}

func TestMongoDisconnectClearsResultSource(t *testing.T) {
	requireIntegration(t)
	engine := startMongoEngine(t, "enode_result_source")
	before, after := resultSourceAfterDisconnect(t, engine)
	t.Logf("input: last offerer disconnects, output: result source %#x:%d → %#x:%d",
		before.SourceID, before.SourcePort, after.SourceID, after.SourcePort)
	if before.SourceID != 0x0b000001 || after.SourceID != 0 || after.SourcePort != 0 {
		t.Fatalf("want 0x0b000001 then 0, got %#x then %#x:%d", before.SourceID, after.SourceID, after.SourcePort)
	}
}
