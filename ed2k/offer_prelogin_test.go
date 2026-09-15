package ed2k

import (
	"bytes"
	"testing"

	"enode/storage"
)

// newPreLoginClient builds a session that has sent nothing at all — the state every socket
// is in between accept() and OP_LOGINREQUEST.
//
// newLoginTestRuntime leaves MessageLogin and MessageLowID empty on purpose, and
// sendServerMessage returns early on an empty string, so the only OP_SERVERMESSAGE frames
// these tests can capture are the ones the login gate produced. The firewall probe is
// stubbed for the one case below that does complete a login.
func newPreLoginClient(t *testing.T, engine storage.Engine) (*tcpClient, *recordingConn) {
	t.Helper()
	rt := newLoginTestRuntime(engine)
	rt.firewallProbe = func(*tcpClient) bool { return true }
	conn := &recordingConn{}
	client := newTCPClient(rt, conn, false)
	if client.isLogged() {
		t.Fatal("setup: a freshly accepted session must not be logged in")
	}
	return client, conn
}

// frameFor renders one item list into its wire frame, so two can be concatenated into a
// single segment and handed to handleBytes — the only way to reach processPacketData's
// Excess recursion, which is what the gate's latch exists for.
func frameFor(t *testing.T, items []PacketItem) []byte {
	t.Helper()
	wire, err := MakePacket(PrED2K, items)
	if err != nil {
		t.Fatal(err)
	}
	return append([]byte(nil), wire.Bytes()...)
}

// segment concatenates frames into one read's worth of bytes. append(a, b...) could write
// into a's backing array, so each frame is copied into a fresh slice.
func segment(frames ...[]byte) []byte {
	var out []byte
	for _, f := range frames {
		out = append(out, f...)
	}
	return out
}

// TestOfferFilesBeforeLoginStoresNothingAndDropsSession is the bug this file exists for.
//
// A pre-login session has no identity — handShake is the only place c.logged and
// c.info.StoreID are set — so every record it published landed under
// {ID: 0, Port: 0, Hash: nil}. Those rows are unreclaimable on the default engine:
// run()'s teardown calls Storage.Disconnect only for a session that was logged in, and
// MemoryEngine.CleanupStale cannot expire a source at all because Source carries no
// timestamp. They survived for the lifetime of the process and were served to real
// clients, which can do nothing with an address of 0:0.
func TestOfferFilesBeforeLoginStoresNothingAndDropsSession(t *testing.T) {
	engine := storage.NewMemoryEngine()
	client, conn := newPreLoginClient(t, engine)
	t.Logf("input: OP_OFFERFILES carrying 3 files on a session that never sent OP_LOGINREQUEST")

	offerFiles(t, client, 0, 3)

	msgs := serverMessages(t, conn)
	sources := engine.GetSourcesByHash(offerHash(0))
	t.Logf("output: stored=%d sources=%d offeredFiles=%d messages=%q closed=%d reason=%q",
		engine.FilesCount(), len(sources), client.offeredFiles, msgs, conn.closed, client.getCloseReason())

	if engine.FilesCount() != 0 {
		t.Errorf("stored %d files, want 0 — an unauthenticated session published to the index", engine.FilesCount())
	}
	if len(sources) != 0 {
		t.Errorf("stored %d sources, want 0 — this is the unroutable {ID:0,Port:0} row", len(sources))
	}
	// Zero, not three: the gate runs in handleED2K before handleOfferFiles is entered, so
	// a refused session cannot spend any of its own publish quota.
	if client.offeredFiles != 0 {
		t.Errorf("offeredFiles=%d, want 0 — the gate must refuse before the handler counts", client.offeredFiles)
	}
	if len(msgs) != 1 || msgs[0] != msgNotLoggedIn {
		t.Errorf("messages=%q, want exactly one %q", msgs, msgNotLoggedIn)
	}
	if conn.closed != 1 {
		t.Errorf("closed=%d, want 1", conn.closed)
	}
	if got := client.getCloseReason(); got != "not-logged-in" {
		t.Errorf("close reason=%q, want %q", got, "not-logged-in")
	}
}

// TestOfferFilesBeforeLoginSpeaksOncePerSegment pins the loginGateTripped latch.
//
// closeWithReason only closes the socket; it does not stop dispatch of bytes that already
// arrived, because processPacketData recurses into packet.Excess after handlePacket
// returns. Without the latch every buffered frame in the segment would produce its own
// warning, its own OP_SERVERMESSAGE and its own redundant Close — and a minimal
// OP_OFFERFILES is ten bytes, so one 4096-byte read holds hundreds of them.
func TestOfferFilesBeforeLoginSpeaksOncePerSegment(t *testing.T) {
	engine := storage.NewMemoryEngine()
	client, conn := newPreLoginClient(t, engine)
	seg := segment(frameFor(t, offerItems(0, 1)), frameFor(t, offerItems(1, 1)))
	t.Logf("input: one %d-byte segment holding two OP_OFFERFILES frames, no login", len(seg))

	client.handleBytes(seg)

	msgs := serverMessages(t, conn)
	t.Logf("output: stored=%d messages=%q closed=%d reason=%q",
		engine.FilesCount(), msgs, conn.closed, client.getCloseReason())

	if len(msgs) != 1 {
		t.Errorf("sent %d messages, want 1 — the latch did not hold across the buffered packet", len(msgs))
	}
	if conn.closed != 1 {
		t.Errorf("closed=%d, want 1 — the session was dropped once per frame", conn.closed)
	}
	if engine.FilesCount() != 0 {
		t.Errorf("stored %d files, want 0", engine.FilesCount())
	}
}

// TestOfferFilesPipelinedBehindAFailedLoginIsRejected covers the one live session state
// that can actually reach the gate on a real connection.
//
// handleLoginRequest logs and returns *without* closing when the payload does not parse,
// unlike every other login refusal (already-logged-in, duplicate-login,
// lowid-pool-exhausted, storage-connect-failed), all of which close. So a socket whose
// login was malformed stays open, un-logged, and whatever it pipelined behind that login
// is dispatched next.
func TestOfferFilesPipelinedBehindAFailedLoginIsRejected(t *testing.T) {
	engine := storage.NewMemoryEngine()
	client, conn := newPreLoginClient(t, engine)
	// A 4-byte login payload: ParseLoginRequest's 16-byte hash read short-reads and the
	// whole request is rejected as ErrOutOfBounds.
	truncated := frameFor(t, []PacketItem{
		{Type: TypeUint8, Value: OpLoginRequest},
		{Type: TypeUint32, Value: uint32(0)},
	})
	seg := segment(truncated, frameFor(t, offerItems(0, 2)))
	t.Logf("input: one segment = truncated OP_LOGINREQUEST (%d bytes) + OP_OFFERFILES with 2 files", len(truncated))

	client.handleBytes(seg)

	msgs := serverMessages(t, conn)
	t.Logf("output: logged=%t stored=%d messages=%q closed=%d reason=%q",
		client.isLogged(), engine.FilesCount(), msgs, conn.closed, client.getCloseReason())

	if client.isLogged() {
		t.Fatal("a truncated login must not establish a session")
	}
	if engine.FilesCount() != 0 {
		t.Errorf("stored %d files, want 0 — the offer behind a failed login was published", engine.FilesCount())
	}
	if got := client.getCloseReason(); got != "not-logged-in" {
		t.Errorf("close reason=%q, want %q", got, "not-logged-in")
	}
	if len(msgs) != 1 || msgs[0] != msgNotLoggedIn {
		t.Errorf("messages=%q, want exactly one %q", msgs, msgNotLoggedIn)
	}
}

// TestOfferFilesPipelinedBehindASuccessfulLoginIsStored proves the gate leaves no window
// for a client that does not wait for OP_IDCHANGE before publishing.
//
// Dispatch is sequential on this connection's goroutine and processPacketData recurses
// into packet.Excess only after handlePacket has returned, so the login is complete —
// including its blocking dial-back probe — before the offer is read. This is the exact
// shape tests/interop/client_test.go sends to the live server.
func TestOfferFilesPipelinedBehindASuccessfulLoginIsStored(t *testing.T) {
	engine := storage.NewMemoryEngine()
	client, conn := newPreLoginClient(t, engine)
	login := frameFor(t, loginItems(bytes.Repeat([]byte{0x3c}, 16), 0, 4662))
	seg := segment(login, frameFor(t, offerItems(0, 2)))
	t.Logf("input: one %d-byte segment = OP_LOGINREQUEST + OP_OFFERFILES with 2 files", len(seg))

	client.handleBytes(seg)

	msgs := serverMessages(t, conn)
	t.Logf("output: logged=%t stored=%d offeredFiles=%d messages=%q closed=%d",
		client.isLogged(), engine.FilesCount(), client.offeredFiles, msgs, conn.closed)

	if !client.isLogged() {
		t.Fatal("the login in this segment should have succeeded")
	}
	if engine.FilesCount() != 2 {
		t.Errorf("stored %d files, want 2 — the gate refused a legitimate pipelined offer", engine.FilesCount())
	}
	if conn.closed != 0 {
		t.Errorf("closed=%d, want 0", conn.closed)
	}
	for _, m := range msgs {
		if m == msgNotLoggedIn {
			t.Errorf("the session was told %q despite being logged in", m)
		}
	}
}

// TestOfferFilesAfterLoginIsUnchanged is the happy-path guard for this change. It overlaps
// the limit tests, deliberately: those would also fail if the gate refused a logged-in
// session, but nothing in them says *why*, and a regression here is the one that matters.
func TestOfferFilesAfterLoginIsUnchanged(t *testing.T) {
	engine := storage.NewMemoryEngine()
	client, conn := newOfferLimitClient(t, engine, 0, 0)
	t.Logf("input: OP_OFFERFILES carrying 3 files on a logged-in session, both limits unlimited")

	offerFiles(t, client, 0, 3)

	msgs := serverMessages(t, conn)
	t.Logf("output: stored=%d offeredFiles=%d messages=%q closed=%d",
		engine.FilesCount(), client.offeredFiles, msgs, conn.closed)

	if engine.FilesCount() != 3 {
		t.Errorf("stored %d files, want 3", engine.FilesCount())
	}
	if client.offeredFiles != 3 {
		t.Errorf("offeredFiles=%d, want 3", client.offeredFiles)
	}
	if len(msgs) != 0 {
		t.Errorf("messages=%q, want none", msgs)
	}
	if conn.closed != 0 {
		t.Errorf("closed=%d, want 0", conn.closed)
	}
}

// TestEveryOpcodeButLoginAndDisconnectIsGated pins the deny-by-default decision, including
// for opcodes that reach handleED2K's default branch: a pre-login client has no business
// sending those either, so an unrecognised one ends the session rather than being logged
// and ignored.
func TestEveryOpcodeButLoginAndDisconnectIsGated(t *testing.T) {
	gated := []struct {
		name   string
		opcode uint8
	}{
		{"OP_GETSERVERLIST", OpGetServerList},
		{"OP_OFFERFILES", OpOfferFiles},
		{"OP_GETSOURCES", OpGetSources},
		{"OP_GETSOURCES_OBFU", OpGetSourcesObfu},
		{"OP_GETSOURCES_IPV6", OpGetSourcesIPv6},
		{"OP_SEARCHREQUEST", OpSearchRequest},
		{"OP_QUERY_MORE_RESULT", OpQueryMoreResult},
		{"OP_CALLBACKREQUEST", OpCallbackRequest},
		// No constant: 0x1a reaches handleED2K's default branch, which is the point.
		{"OP_SEARCH_USER (unhandled)", 0x1a},
	}
	for _, tc := range gated {
		t.Run(tc.name, func(t *testing.T) {
			client, conn := newPreLoginClient(t, storage.NewMemoryEngine())
			t.Logf("input: %s (0x%02x) on a session that never logged in", tc.name, tc.opcode)

			client.handleED2K(tc.opcode, NewBufferFromBytes(nil))

			msgs := serverMessages(t, conn)
			t.Logf("output: messages=%q closed=%d reason=%q", msgs, conn.closed, client.getCloseReason())

			if got := client.getCloseReason(); got != "not-logged-in" {
				t.Errorf("close reason=%q, want %q", got, "not-logged-in")
			}
			if conn.closed != 1 {
				t.Errorf("closed=%d, want 1", conn.closed)
			}
			if len(msgs) != 1 || msgs[0] != msgNotLoggedIn {
				t.Errorf("messages=%q, want exactly one %q", msgs, msgNotLoggedIn)
			}
		})
	}
}

// TestDisconnectIsStillHonouredBeforeLogin guards the other half of the exemption list.
// setCloseReason keeps the first reason it is given, so an OP_DISCONNECT wrongly routed
// through the gate would be invisible except through the reason it left behind.
func TestDisconnectIsStillHonouredBeforeLogin(t *testing.T) {
	client, conn := newPreLoginClient(t, storage.NewMemoryEngine())
	t.Logf("input: OP_DISCONNECT (0x%02x) on a session that never logged in", OpDisconnect)

	client.handleED2K(OpDisconnect, NewBufferFromBytes(nil))

	msgs := serverMessages(t, conn)
	t.Logf("output: messages=%q closed=%d reason=%q", msgs, conn.closed, client.getCloseReason())

	if got := client.getCloseReason(); got != "client-disconnect" {
		t.Errorf("close reason=%q, want %q — a client leaving must not be told it is unauthenticated", got, "client-disconnect")
	}
	if len(msgs) != 0 {
		t.Errorf("messages=%q, want none", msgs)
	}
}

// TestLoginIsStillReachableBeforeLogin is the obvious one, and the one whose failure would
// lock every client out of the server: the opcode that creates a session cannot require a
// session. Asserted through the real dispatcher rather than handleLoginRequest directly,
// since the gate lives in handleED2K.
func TestLoginIsStillReachableBeforeLogin(t *testing.T) {
	engine := storage.NewMemoryEngine()
	client, conn := newPreLoginClient(t, engine)
	t.Logf("input: OP_LOGINREQUEST (0x%02x) through handleED2K on a fresh session", OpLoginRequest)

	p := loginPacket(t, bytes.Repeat([]byte{0x2d}, 16), 0, 4662)
	client.handlePacket(p)

	info := client.snapshotInfo()
	t.Logf("output: logged=%t id=%d lowID=%t closed=%d reason=%q",
		client.isLogged(), info.ID, info.LowID, conn.closed, client.getCloseReason())

	if !client.isLogged() {
		t.Fatal("the login gate refused the login itself")
	}
	if conn.closed != 0 {
		t.Errorf("closed=%d, want 0", conn.closed)
	}
	for _, m := range serverMessages(t, conn) {
		if m == msgNotLoggedIn {
			t.Errorf("the login was answered with %q", m)
		}
	}
}
