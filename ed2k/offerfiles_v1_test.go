package ed2k

import (
	"bytes"
	"testing"
	"time"

	"enode/storage"
)

// TestStringNamedTagRoundTrip pins the wire shape of a string-named tag: old format,
// type byte, uint16 name length, the name, then the value — what every client's tag
// loop skips by name when it does not know it.
func TestStringNamedTagRoundTrip(t *testing.T) {
	tag := Tag{Type: TypeUint32, Name: TagNameOfferFilesBatchMax, Data: uint32(200)}
	n, err := TagsLength([]Tag{tag})
	if err != nil {
		t.Fatal(err)
	}
	buf := NewBuffer(n)
	if err := buf.PutTags([]Tag{tag}); err != nil {
		t.Fatal(err)
	}
	t.Logf("input: %+v", tag)
	t.Logf("output: % x", buf.Bytes())

	want := []byte{1, 0, 0, 0, TypeUint32, byte(len(TagNameOfferFilesBatchMax)), 0}
	want = append(want, TagNameOfferFilesBatchMax...)
	want = append(want, 200, 0, 0, 0)
	if !bytes.Equal(buf.Bytes(), want) {
		t.Fatalf("wire = % x, want % x", buf.Bytes(), want)
	}
	tags, err := NewBufferFromBytes(buf.Bytes()).GetTags()
	if err != nil {
		t.Fatal(err)
	}
	if len(tags) != 1 || tags[0].Name != TagNameOfferFilesBatchMax || tags[0].Type != TypeUint32 || tags[0].Value != uint64(200) {
		t.Fatalf("decoded %+v", tags)
	}
}

func TestLoginRequestsOfferFilesV1(t *testing.T) {
	cases := []struct {
		name string
		tags []NamedTag
		want bool
	}{
		{"absent", nil, false},
		{"uint32 1", []NamedTag{{Name: TagNameOfferFilesVersion, Type: TypeUint32, Value: uint64(1)}}, true},
		{"uint32 2 (a later version also speaks 1)", []NamedTag{{Name: TagNameOfferFilesVersion, Type: TypeUint32, Value: uint64(2)}}, true},
		{"uint32 0", []NamedTag{{Name: TagNameOfferFilesVersion, Type: TypeUint32, Value: uint64(0)}}, false},
		{"uint8 1 (wrong type)", []NamedTag{{Name: TagNameOfferFilesVersion, Type: TypeUint8, Value: uint64(1)}}, false},
		{"string", []NamedTag{{Name: TagNameOfferFilesVersion, Type: TypeString, Value: "1"}}, false},
		{"other name", []NamedTag{{Name: "offerfiles", Type: TypeUint32, Value: uint64(1)}}, false},
	}
	for _, tc := range cases {
		got := LoginRequestsOfferFilesV1(tc.tags)
		t.Logf("input: %s %+v output: %t", tc.name, tc.tags, got)
		if got != tc.want {
			t.Errorf("%s: got %t, want %t", tc.name, got, tc.want)
		}
	}
}

// TestOfferBucketPaces drives the bucket with a fake clock: full at the start, one
// batch per interval after, smaller batches proportionally cheaper.
func TestOfferBucketPaces(t *testing.T) {
	p := &offerV1Policy{BatchMax: 200, Interval: 500 * time.Millisecond}
	t0 := time.Unix(1000, 0)
	b := newOfferBucket(p, t0)
	steps := []struct {
		at   time.Duration
		cost uint32
		want time.Duration
	}{
		{0, 200, 0},                      // starts full: the first batch goes at once
		{0, 200, 500 * time.Millisecond}, // a second right after waits one interval
		{500 * time.Millisecond, 0, 0},   // the deficit was paid off by then
		{500 * time.Millisecond, 100, 250 * time.Millisecond},
		{2 * time.Second, 50, 0},  // refilled, capped at one batch
		{2 * time.Second, 150, 0}, // ...which is exactly what is left
		{2 * time.Second, 1, 2500 * time.Microsecond},
	}
	for i, s := range steps {
		got := b.reserve(t0.Add(s.at), s.cost)
		t.Logf("input: step=%d at=%s cost=%d output: wait=%s", i, s.at, s.cost, got)
		if d := got - s.want; d > time.Microsecond || d < -time.Microsecond {
			t.Errorf("step %d: wait %s, want %s", i, got, s.want)
		}
	}
}

func TestOfferFilesV1Problem(t *testing.T) {
	ok := TCPRuntimeConfig{SoftFileLimit: 10000, HardFileLimit: 20000,
		OfferFilesV1: OfferFilesV1Config{Enabled: true, BatchMax: 200, MinInterval: 500 * time.Millisecond}}
	cases := []struct {
		name    string
		mutate  func(*TCPRuntimeConfig)
		wantErr bool
	}{
		{"valid", func(*TCPRuntimeConfig) {}, false},
		{"off", func(c *TCPRuntimeConfig) { c.OfferFilesV1.Enabled = false }, false},
		{"soft unlimited", func(c *TCPRuntimeConfig) { c.SoftFileLimit = 0 }, true},
		{"hard unlimited", func(c *TCPRuntimeConfig) { c.HardFileLimit = 0 }, true},
		{"batch 0", func(c *TCPRuntimeConfig) { c.OfferFilesV1.BatchMax = 0 }, true},
		{"interval 0", func(c *TCPRuntimeConfig) { c.OfferFilesV1.MinInterval = 0 }, true},
		{"hard == batch", func(c *TCPRuntimeConfig) { c.HardFileLimit = 200 }, true},
	}
	for _, tc := range cases {
		cfg := ok
		tc.mutate(&cfg)
		err := OfferFilesV1Problem(cfg)
		if !cfg.OfferFilesV1.Enabled && err != nil {
			// Off is reported as errOfferV1Off; callers check Enabled first.
			err = nil
		}
		t.Logf("input: %s output: err=%v", tc.name, err)
		if (err != nil) != tc.wantErr {
			t.Errorf("%s: err=%v, wantErr=%t", tc.name, err, tc.wantErr)
		}
	}
}

// TestOfferFilesV1AdvertisedOnlyToAskingClient: the advertisement goes to a client
// that asked, in the post-login OP_SERVERIDENT, all five tags once each; a legacy
// client gets none, and neither does the OP_GETSERVERLIST answer.
func TestOfferFilesV1AdvertisedOnlyToAskingClient(t *testing.T) {
	for _, asks := range []bool{true, false} {
		client, conn := newOfferV1Client(t, storage.NewMemoryEngine(), asks, 200, 500*time.Millisecond)
		tags := identTags(t, conn)
		t.Logf("input: client asks=%t output: post-login ident tags=%v", asks, tags)
		v1Names := []string{"0x88", "0x89", TagNameOfferFilesVersion, TagNameOfferFilesBatchMax, TagNameOfferFilesMinIntvMs}
		for _, name := range v1Names {
			tg, found := tags[name]
			if !asks {
				if found {
					t.Errorf("legacy client got %s", name)
				}
				continue
			}
			if !found || tg.Type != TypeUint32 {
				t.Errorf("v1 client: tag %s = %+v (found=%t), want uint32", name, tg, found)
			}
		}
		if asks {
			want := map[string]uint64{"0x88": 10000, "0x89": 20000, TagNameOfferFilesVersion: 1,
				TagNameOfferFilesBatchMax: 200, TagNameOfferFilesMinIntvMs: 500}
			for name, v := range want {
				if tags[name].Value != v {
					t.Errorf("%s = %v, want %d", name, tags[name].Value, v)
				}
			}
		}

		clearWritten(conn)
		client.handleGetServerList()
		later := identTags(t, conn)
		t.Logf("output: OP_GETSERVERLIST ident tags=%v", later)
		if _, found := later[TagNameOfferFilesVersion]; found {
			t.Errorf("asks=%t: the OP_GETSERVERLIST ident repeated the v1 advertisement", asks)
		}
	}
}

// TestOfferFilesV1NotAdvertisableIsLegacy: with soft unlimited, a client that asks is
// told nothing and treated as a legacy one.
func TestOfferFilesV1NotAdvertisableIsLegacy(t *testing.T) {
	rt := newOfferV1Runtime(storage.NewMemoryEngine(), 200, 500*time.Millisecond)
	cfg := *rt.tcp()
	cfg.SoftFileLimit = 0
	rt.tcpCfg.Store(&cfg)
	client, conn := loginOfferV1Client(t, rt, true)
	tags := identTags(t, conn)
	t.Logf("input: softLimit=0, client asks output: offerV1=%v tags=%v", client.offerV1, tags)
	if client.offerV1 != nil {
		t.Error("session holds a v1 policy the server could not advertise")
	}
	if _, found := tags[TagNameOfferFilesVersion]; found {
		t.Error("offerfiles_v advertised with an invalid configuration")
	}
}

// TestOfferFilesV1OverBatchNotIndexedSessionStays: a v1 packet over batch_max but
// under the hard limit is not indexed and the session stays up; the same packet from
// a legacy client is indexed.
func TestOfferFilesV1OverBatchNotIndexedSessionStays(t *testing.T) {
	for _, asks := range []bool{true, false} {
		engine := storage.NewMemoryEngine()
		client, conn := newOfferV1Client(t, engine, asks, 3, 10*time.Millisecond)
		offerFiles(t, client, 0, 5)
		t.Logf("input: batchMax=3 asks=%t, offer of 5 output: stored=%d closed=%d overBatch=%d",
			asks, engine.FilesCount(), conn.closed, client.server.blocks.offerOverBatch.Load())
		if conn.closed != 0 {
			t.Errorf("asks=%t: session closed", asks)
		}
		want := 5
		if asks {
			want = 0
		}
		if engine.FilesCount() != want {
			t.Errorf("asks=%t: stored %d, want %d", asks, engine.FilesCount(), want)
		}
		// A packet within the batch is still indexed after the oversized one.
		offerFiles(t, client, 10, 3)
		if asks && engine.FilesCount() != 3 {
			t.Errorf("v1: stored %d after a valid batch, want 3", engine.FilesCount())
		}
	}
}

// TestOfferFilesV1HardLimitStillCloses: the hard limit applies to v1 sessions as to
// everyone, ahead of the batch check.
func TestOfferFilesV1HardLimitStillCloses(t *testing.T) {
	rt := newOfferV1Runtime(storage.NewMemoryEngine(), 3, 10*time.Millisecond)
	cfg := *rt.tcp()
	cfg.HardFileLimit = 5
	rt.tcpCfg.Store(&cfg)
	client, conn := loginOfferV1Client(t, rt, true)
	offerFiles(t, client, 0, 5)
	t.Logf("input: hardLimit=5 batchMax=3, offer of 5 output: closed=%d reason=%s", conn.closed, client.getCloseReason())
	if conn.closed == 0 || client.getCloseReason() != "file-hard-limit" {
		t.Errorf("closed=%d reason=%s, want file-hard-limit", conn.closed, client.getCloseReason())
	}
}

// TestOfferFilesV1EarlyBatchWaits: a batch that arrives before it is due waits, and
// is indexed, not dropped.
func TestOfferFilesV1EarlyBatchWaits(t *testing.T) {
	engine := storage.NewMemoryEngine()
	const interval = 200 * time.Millisecond
	client, conn := newOfferV1Client(t, engine, true, 3, interval)
	start := time.Now()
	offerFiles(t, client, 0, 3)
	first := time.Since(start)
	offerFiles(t, client, 3, 3)
	both := time.Since(start)
	t.Logf("input: batchMax=3 interval=%s, two batches of 3 back to back output: first=%s both=%s stored=%d paced=%d",
		interval, first, both, engine.FilesCount(), client.server.blocks.offerPaced.Load())
	if first > interval/2 {
		t.Errorf("first batch took %s; the bucket starts full", first)
	}
	if both < interval-20*time.Millisecond {
		t.Errorf("second batch processed after %s, want about %s", both, interval)
	}
	if engine.FilesCount() != 6 || conn.closed != 0 {
		t.Errorf("stored=%d closed=%d, want 6 and 0", engine.FilesCount(), conn.closed)
	}
}

// TestOfferFilesV1SurvivesHandover: the policy a session was advertised moves to the
// successor process with it.
func TestOfferFilesV1SurvivesHandover(t *testing.T) {
	client, _ := newOfferV1Client(t, storage.NewMemoryEngine(), true, 7, 300*time.Millisecond)
	st := client.exportState()
	succ := newTCPClient(client.server, &recordingConn{}, false)
	succ.applyState(st)
	t.Logf("input: %+v output: %+v", client.offerV1, succ.offerV1)
	if succ.offerV1 == nil || succ.offerV1.offerV1Policy != client.offerV1.offerV1Policy {
		t.Fatalf("successor policy %+v, want %+v", succ.offerV1, client.offerV1)
	}
}

// newOfferV1Runtime is newOfferLimitClient's runtime with v1 on and the default limits.
func newOfferV1Runtime(engine storage.Engine, batchMax int, interval time.Duration) *ServerRuntime {
	rt := NewServerRuntime(TCPRuntimeConfig{
		Address:           "127.0.0.1",
		Port:              4661,
		Hash:              []byte("1111111111111111"),
		AllowLowIDs:       true,
		ConnectionTimeout: 50 * time.Millisecond,
		SoftFileLimit:     10000,
		HardFileLimit:     20000,
		OfferFilesV1:      OfferFilesV1Config{Enabled: true, BatchMax: batchMax, MinInterval: interval},
	}, UDPRuntimeConfig{}, engine)
	rt.firewallProbe = func(*tcpClient) bool { return true }
	return rt
}

func newOfferV1Client(t *testing.T, engine storage.Engine, asks bool, batchMax int, interval time.Duration) (*tcpClient, *recordingConn) {
	t.Helper()
	return loginOfferV1Client(t, newOfferV1Runtime(engine, batchMax, interval), asks)
}

// loginOfferV1Client logs a session in, with the offerfiles_v request tag when asks.
func loginOfferV1Client(t *testing.T, rt *ServerRuntime, asks bool) (*tcpClient, *recordingConn) {
	t.Helper()
	conn := &recordingConn{}
	client := newTCPClient(rt, conn, false)
	items := loginItems(bytes.Repeat([]byte{0x5a}, 16), 0, 4662)
	if asks {
		items[len(items)-1].Value = []Tag{{Type: TypeUint32, Name: TagNameOfferFilesVersion, Data: uint32(1)}}
	}
	dispatchIncomingTCPPacket(t, client, items)
	if !client.logged {
		t.Fatal("setup: login failed")
	}
	return client, conn
}

// identTags decodes the tags of the last OP_SERVERIDENT the session was sent.
func identTags(t *testing.T, conn *recordingConn) map[string]NamedTag {
	t.Helper()
	frames := conn.allWritten()
	for i := len(frames) - 1; i >= 0; i-- {
		f := frames[i]
		if len(f) < 6 || f[5] != OpServerIdent {
			continue
		}
		payload := f[6:]
		switch f[0] {
		case PrED2K:
		case PrZlib:
			// With the v1 tags the packet is large enough to be sent compressed.
			var err error
			if payload, err = InflateZlibPayload(payload); err != nil {
				t.Fatalf("inflate: %v", err)
			}
		default:
			continue
		}
		b := NewBufferFromBytes(payload)
		_ = b.Get(16)
		_, _ = b.GetUInt32LE()
		_, _ = b.GetUInt16LE()
		tags, err := b.GetTags()
		if err != nil {
			t.Fatalf("tag decode: %v", err)
		}
		out := map[string]NamedTag{}
		for _, tg := range tags {
			if _, dup := out[tg.Name]; dup {
				t.Errorf("tag %s sent twice", tg.Name)
			}
			out[tg.Name] = tg
		}
		return out
	}
	t.Fatal("no OP_SERVERIDENT written")
	return nil
}

func clearWritten(conn *recordingConn) {
	conn.mu.Lock()
	conn.written = nil
	conn.mu.Unlock()
}
