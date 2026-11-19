package storage

import "testing"

// updateClientMovesSources publishes one file from a LowID client, moves the client to
// its HighID on another port and returns the sources and search result after.
func updateClientMovesSources(t *testing.T, engine Engine) (ClientInfo, []Source, File) {
	t.Helper()
	info := ClientInfo{ID: 0x00123457, IPv4: 0x0100000a, Port: 4662, LowID: true, Hash: []byte("update-client-01")}
	var err error
	if info.StoreID, err = engine.Connect(info); err != nil {
		t.Fatal(err)
	}
	file := File{Hash: []byte("update-client-f1"), Name: "updateclient.iso", Size: 10, Type: "Pro"}
	engine.AddFile(file, info)
	moved := info
	moved.ID, moved.Port, moved.LowID = info.IPv4, 5000, false
	if err := engine.UpdateClient(info.ID, info.Port, moved); err != nil {
		t.Fatal(err)
	}
	found := engine.FindBySearch(&SearchExpr{Kind: SearchText, Text: "updateclient"})
	if len(found) != 1 {
		t.Fatalf("want 1 result, got %d", len(found))
	}
	return moved, engine.GetSources(file.Hash, file.Size), found[0]
}

func checkUpdatedClient(t *testing.T, engine Engine, moved ClientInfo, sources []Source, result File) {
	t.Helper()
	t.Logf("input: LowID 0x00123457:4662 → %#x:%d; output: sources=%v result source %#x:%d",
		moved.ID, moved.Port, sources, result.SourceID, result.SourcePort)
	if len(sources) != 1 || sources[0].ID != moved.ID || sources[0].Port != moved.Port {
		t.Fatalf("sources = %+v, want one at %#x:%d", sources, moved.ID, moved.Port)
	}
	if result.SourceID != moved.ID || result.SourcePort != moved.Port {
		t.Fatalf("result source %#x:%d, want %#x:%d", result.SourceID, result.SourcePort, moved.ID, moved.Port)
	}
	if !engine.IsConnected(moved) {
		t.Fatal("client not connected after the update")
	}
	engine.Disconnect(moved)
	if got := engine.GetSources([]byte("update-client-f1"), 10); len(got) != 0 {
		t.Fatalf("disconnect after the update left %d source(s)", len(got))
	}
}

func TestMemoryUpdateClientMovesSources(t *testing.T) {
	engine := NewMemoryEngine()
	moved, sources, result := updateClientMovesSources(t, engine)
	checkUpdatedClient(t, engine, moved, sources, result)
	if engine.ClientsCount() != 0 {
		t.Fatalf("ClientsCount = %d after disconnect", engine.ClientsCount())
	}
}

// An unknown session is not an error and creates nothing.
func TestMemoryUpdateClientUnknownSession(t *testing.T) {
	engine := NewMemoryEngine()
	if err := engine.UpdateClient(1, 2, ClientInfo{StoreID: 99, ID: 3, Port: 4}); err != nil {
		t.Fatal(err)
	}
	if engine.ClientsCount() != 0 {
		t.Fatal("UpdateClient created a client")
	}
}

// UpdateClientIPv6 moves a session's sources to a new IPv6 and reachability, and a
// withdraw takes the address off them.
func TestMemoryUpdateClientIPv6(t *testing.T) {
	engine := NewMemoryEngine()
	info := ClientInfo{ID: 0x00123457, IPv4: 0x0100000a, Port: 4662, LowID: true, Hash: []byte("update-client-v6")}
	var err error
	if info.StoreID, err = engine.Connect(info); err != nil {
		t.Fatal(err)
	}
	file := File{Hash: []byte("update-client-f6"), Name: "updatev6.iso", Size: 10, Type: "Pro"}
	engine.AddFile(file, info)
	before := engine.GetSources(file.Hash, file.Size)

	addr := []byte{0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0a}
	info.IPv6, info.IPv6Reachable = addr, true
	if err := engine.UpdateClientIPv6(info); err != nil {
		t.Fatal(err)
	}
	published := engine.GetSources(file.Hash, file.Size)

	info.IPv6, info.IPv6Reachable = nil, false
	if err := engine.UpdateClientIPv6(info); err != nil {
		t.Fatal(err)
	}
	withdrawn := engine.GetSources(file.Hash, file.Size)
	t.Logf("input: no ipv6 -> %x reachable -> withdrawn; output: %+v / %+v / %+v", addr, before, published, withdrawn)
	if len(before) != 1 || len(before[0].IPv6) != 0 {
		t.Fatalf("before = %+v", before)
	}
	if len(published) != 1 || string(published[0].IPv6) != string(addr) || !published[0].IPv6Reachable {
		t.Fatalf("published = %+v", published)
	}
	if len(withdrawn) != 1 || len(withdrawn[0].IPv6) != 0 || withdrawn[0].IPv6Reachable {
		t.Fatalf("withdrawn = %+v", withdrawn)
	}
	// A slice handed out before the update is not written to.
	if string(published[0].IPv6) != string(addr) {
		t.Fatal("an earlier source list changed under its reader")
	}
	if err := engine.UpdateClientIPv6(ClientInfo{StoreID: 99}); err != nil {
		t.Fatal(err)
	}
}
