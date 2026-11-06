package ed2k

import (
	"bytes"
	"testing"

	"enode/storage"
)

// emule-qt#137: storage holds the hash online with no session behind it — a failed
// Disconnect, or a session a handover did not carry over. The login releases the row
// and goes on, instead of "Already connected from another session" until a cold
// restart.
func TestDuplicateLoginReleasesOrphanedRow(t *testing.T) {
	engine := storage.NewMemoryEngine()
	rt := newHandoverRuntime(engine)
	hash := bytes.Repeat([]byte{0xd1}, 16)
	staleID, err := engine.Connect(storage.ClientInfo{Hash: hash, ID: 0x01020304, Port: 4662})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("input: orphaned row hash=%x storeID=%d, no session", hash, staleID)

	conn := v4Conn()
	c := newTCPClient(rt, conn, false)
	c.handlePacket(loginPacket(t, hash, 0, 4662))
	t.Logf("output: logged=%t reason=%q storeID=%d", c.logged, c.getCloseReason(), c.info.StoreID)

	if !c.logged {
		t.Fatalf("login refused over an orphaned row (reason=%q)", c.getCloseReason())
	}
	if c.info.StoreID == staleID {
		t.Fatal("the login reused the orphaned row instead of a fresh one")
	}
	if rt.sessionByHash(hash) != c {
		t.Fatal("hash index does not point at the new session")
	}
	if engine.ClientsCount() != 1 {
		t.Fatalf("clients=%d want 1: the orphaned row was not released", engine.ClientsCount())
	}
}

// A hash between Connect and registerSession in another login is held: a parallel
// login must not take that fresh row for an orphan.
func TestDuplicateLoginRefusedWhileHashHandshaking(t *testing.T) {
	engine := storage.NewMemoryEngine()
	rt := newHandoverRuntime(engine)
	hash := bytes.Repeat([]byte{0xd2}, 16)
	done := rt.beginHandshake(hash)
	defer done()
	if _, err := engine.Connect(storage.ClientInfo{Hash: hash, ID: 0x01020304, Port: 4662}); err != nil {
		t.Fatal(err)
	}
	t.Logf("input: hash=%x mid-handshake, row written, not yet indexed", hash)

	c := newTCPClient(rt, v4Conn(), false)
	c.handlePacket(loginPacket(t, hash, 0, 4662))
	t.Logf("output: logged=%t reason=%q", c.logged, c.getCloseReason())

	if c.logged {
		t.Fatal("a parallel login freed the row of a handshake in progress")
	}
	if got := c.getCloseReason(); got != "duplicate-login" {
		t.Fatalf("reason=%q want duplicate-login", got)
	}
	if !engine.IsConnected(storage.ClientInfo{Hash: hash}) {
		t.Fatal("the handshaking session's row was released")
	}
}

func TestHandshakeMarkClearsAfterLogin(t *testing.T) {
	rt := newHandoverRuntime(storage.NewMemoryEngine())
	hash := bytes.Repeat([]byte{0xd3}, 16)
	c := newTCPClient(rt, v4Conn(), false)
	c.handlePacket(loginPacket(t, hash, 0, 4662))
	if !c.logged {
		t.Fatalf("login refused (reason=%q)", c.getCloseReason())
	}
	rt.sessionsMu.RLock()
	n := len(rt.handshaking)
	rt.sessionsMu.RUnlock()
	if n != 0 {
		t.Fatalf("handshaking=%d after login, want 0", n)
	}
}

// A handover successor releases every online row no session of its own holds, and
// keeps the ones its inherited sessions hold.
func TestReleaseOrphanedRowsKeepsHeldSessions(t *testing.T) {
	engine := storage.NewMemoryEngine()
	rt := newHandoverRuntime(engine)
	held := bytes.Repeat([]byte{0xd4}, 16)
	orphan := bytes.Repeat([]byte{0xd5}, 16)

	c := newTCPClient(rt, v4Conn(), false)
	c.handlePacket(loginPacket(t, held, 0, 4662))
	if !c.logged {
		t.Fatalf("login refused (reason=%q)", c.getCloseReason())
	}
	if _, err := engine.Connect(storage.ClientInfo{Hash: orphan, ID: 0x05060708, Port: 4663}); err != nil {
		t.Fatal(err)
	}
	t.Logf("input: held=%x (session) orphan=%x (row only)", held, orphan)

	rt.ReleaseOrphanedRows()
	t.Logf("output: held online=%t orphan online=%t",
		engine.IsConnected(storage.ClientInfo{Hash: held}), engine.IsConnected(storage.ClientInfo{Hash: orphan}))

	if !engine.IsConnected(storage.ClientInfo{Hash: held}) {
		t.Fatal("the held session's row was released")
	}
	if engine.IsConnected(storage.ClientInfo{Hash: orphan}) {
		t.Fatal("the orphaned row is still online")
	}
}
