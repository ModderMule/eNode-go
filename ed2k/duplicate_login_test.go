package ed2k

import (
	"bytes"
	"testing"
	"time"

	"enode/storage"
)

func newLoginTestRuntime(engine storage.Engine) *ServerRuntime {
	return NewServerRuntime(TCPRuntimeConfig{
		Address:           "127.0.0.1",
		Port:              4661,
		Hash:              []byte("1111111111111111"),
		AllowLowIDs:       true,
		ConnectionTimeout: 50 * time.Millisecond,
	}, UDPRuntimeConfig{}, engine)
}

func loginPacket(t *testing.T, hash []byte, id uint32, port uint16) *Packet {
	t.Helper()
	wire, err := MakePacket(PrED2K, loginItems(hash, id, port))
	if err != nil {
		t.Fatal(err)
	}
	p := NewPacket()
	if err := p.Init(NewBufferFromBytes(wire.Bytes())); err != nil {
		t.Fatal(err)
	}
	return p
}

// loginItems is the item list loginPacket frames. Split out so a test can concatenate a
// login frame with another packet into one segment and feed the pair to handleBytes.
func loginItems(hash []byte, id uint32, port uint16) []PacketItem {
	return []PacketItem{
		{Type: TypeUint8, Value: OpLoginRequest},
		{Type: TypeHash, Value: hash},
		{Type: TypeUint32, Value: id},
		{Type: TypeUint16, Value: port},
		{Type: TypeTags, Value: []Tag{}},
	}
}

// The security case: the user hash is public — broadcast in OP_HELLO and handed
// out in OP_FOUNDSOURCES_OBFU — so if a duplicate login evicted the existing
// session, any peer could disconnect any user at will. The existing session must
// survive and the newcomer must be the one to go.
func TestDuplicateLoginRejectsNewSessionAndKeepsExisting(t *testing.T) {
	engine := storage.NewMemoryEngine()
	rt := newLoginTestRuntime(engine)
	hash := bytes.Repeat([]byte{0xab}, 16)

	firstConn := &mockConn{}
	first := newTCPClient(rt, firstConn, false)
	first.handlePacket(loginPacket(t, hash, 0, 4662))
	t.Logf("input: first login hash=%x", hash)
	t.Logf("output: first logged=%t storeID=%d closed=%d", first.logged, first.info.StoreID, firstConn.closed)

	if !first.logged {
		t.Fatal("first login should have succeeded")
	}

	// A second connection presenting the same (public) hash.
	secondConn := &mockConn{}
	second := newTCPClient(rt, secondConn, false)
	second.handlePacket(loginPacket(t, hash, 0, 4663))
	t.Logf("input: second login with the same hash from a different connection")
	t.Logf("output: second logged=%t closed=%d reason=%q", second.logged, secondConn.closed, second.getCloseReason())
	t.Logf("output: first still logged=%t closed=%d", first.logged, firstConn.closed)

	if second.logged {
		t.Fatal("duplicate login must not be granted a session")
	}
	if secondConn.closed == 0 {
		t.Fatal("duplicate login must have its connection closed")
	}
	// This is the assertion that matters: the victim keeps their session.
	if firstConn.closed != 0 {
		t.Fatalf("existing session was kicked by a duplicate login (closed=%d)", firstConn.closed)
	}
	if !first.logged {
		t.Fatal("existing session lost its logged state to a duplicate login")
	}
}

// A repeated OP_LOGINREQUEST on one socket used to overwrite c.info.ID while the
// previously allocated LowID stayed in the table. Cleanup frees only the last ID,
// so a socket looping logins drained the 1..0xffffff pool permanently.
func TestRepeatedLoginOnSameConnectionAllocatesOneLowID(t *testing.T) {
	engine := storage.NewMemoryEngine()
	rt := newLoginTestRuntime(engine)
	hash := bytes.Repeat([]byte{0xcd}, 16)

	conn := &mockConn{}
	client := newTCPClient(rt, conn, false)

	client.handlePacket(loginPacket(t, hash, 0, 4662))
	if !client.logged {
		t.Fatal("first login should have succeeded")
	}
	afterFirst := rt.LowIDs.Count()
	firstID := client.info.ID
	t.Logf("input: login #1 -> assignedID=%d, lowIDs in table=%d", firstID, afterFirst)

	const repeats = 5
	for i := 0; i < repeats; i++ {
		client.handlePacket(loginPacket(t, hash, 0, 4662))
	}
	afterRepeats := rt.LowIDs.Count()
	t.Logf("output: after %d more logins -> assignedID=%d, lowIDs in table=%d",
		repeats, client.info.ID, afterRepeats)

	if afterRepeats != afterFirst {
		t.Fatalf("repeated logins leaked LowIDs: %d allocated after 1 login, %d after %d more",
			afterFirst, afterRepeats, repeats)
	}
	if client.info.ID != firstID {
		t.Fatalf("repeated login overwrote the assigned ID: %d -> %d", firstID, client.info.ID)
	}
	if conn.closed == 0 {
		t.Fatal("a duplicate login on an established session should close it")
	}
}

// Once the first session ends, the same hash must be able to log in again —
// otherwise rejecting duplicates would lock users out after any disconnect.
func TestLoginAllowedAgainAfterDisconnect(t *testing.T) {
	engine := storage.NewMemoryEngine()
	rt := newLoginTestRuntime(engine)
	hash := bytes.Repeat([]byte{0xef}, 16)

	first := newTCPClient(rt, &mockConn{}, false)
	first.handlePacket(loginPacket(t, hash, 0, 4662))
	if !first.logged {
		t.Fatal("first login should have succeeded")
	}
	t.Logf("input: first session logged in, storeID=%d", first.info.StoreID)

	engine.Disconnect(first.info)
	t.Logf("input: first session disconnected")

	second := newTCPClient(rt, &mockConn{}, false)
	second.handlePacket(loginPacket(t, hash, 0, 4663))
	t.Logf("output: reconnect logged=%t storeID=%d", second.logged, second.info.StoreID)

	if !second.logged {
		t.Fatal("the same hash must be able to log in again after disconnecting")
	}
}

// MemoryEngine used to key IsConnected on info.ID while MySQL and MongoDB keyed
// on hash. At the point the login path checks, the ed2k ID is still the untrusted
// value from the request, so an ID-keyed check would not see the duplicate.
func TestMemoryEngineIsConnectedKeyedOnHash(t *testing.T) {
	engine := storage.NewMemoryEngine()
	hash := bytes.Repeat([]byte{0x7f}, 16)

	if _, err := engine.Connect(storage.ClientInfo{ID: 12345, Hash: hash, Port: 4662}); err != nil {
		t.Fatal(err)
	}
	t.Logf("input: connected with ID=12345 hash=%x", hash)

	// Same hash, different (and unknown) ID — this is what the login path sees.
	got := engine.IsConnected(storage.ClientInfo{ID: 0, Hash: hash})
	t.Logf("output: IsConnected(ID=0, same hash) = %t", got)
	if !got {
		t.Fatal("IsConnected must match on hash, not on the client-supplied ID")
	}

	other := engine.IsConnected(storage.ClientInfo{ID: 0, Hash: bytes.Repeat([]byte{0x01}, 16)})
	t.Logf("output: IsConnected(different hash) = %t", other)
	if other {
		t.Fatal("IsConnected must not match an unrelated hash")
	}
}
