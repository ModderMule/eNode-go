package ed3k

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"enode/ed3k/ident"
	"enode/storage"
)

// The one-way bridge from ed3k to eD2K (docs/ed2k-tags.md §6 of the spec): a
// node that stored a SOURCE record here may be listed as an eD2K source of a file
// when its Hello has ED2K, it is open in IPv4 on a direct connection, a KEYWORD
// record signed by its key gives the eD2K hash of that file, and the server's own
// TCP connect to its observed address at that port succeeds: ed3k listens on the
// UDP port whose number is the eD2K TCP port (§14.1), and "open" in ed3k is a UDP
// result that says nothing of TCP.

// Bridge defaults.
const (
	DefaultBridgeTestTTL = 30 * time.Minute
	bridgeDialTimeout    = 5 * time.Second
	bridgeTests          = 16 // concurrent TCP tests
)

// BridgeSource is an ed3k node listed on eD2K.
type BridgeSource struct {
	NodeID ident.NodeID
	EP4    netip.AddrPort // also the eD2K TCP endpoint
}

type bridgeTest struct {
	ok      bool
	at      time.Time
	running bool
}

type bridge struct {
	store  storage.Ed3kStore
	ttl    time.Duration
	dial   func(ctx context.Context, ep netip.AddrPort) error
	sem    chan struct{}
	mu     sync.Mutex
	tested map[netip.AddrPort]*bridgeTest
	listed atomic.Uint64
}

// SetBridgeTestTTL sets how long a TCP test result is kept.
func (n *Node) SetBridgeTestTTL(ttl time.Duration) {
	if ttl > 0 {
		n.bridge.ttl = ttl
	}
}

// BridgeSources returns up to limit ed3k nodes to list as eD2K sources of the
// file with this MD4 hash. A node whose TCP test has not run yet is tested in
// the background and left out of this answer.
func (n *Node) BridgeSources(ctx context.Context, ed2k [16]byte, limit int) []BridgeSource {
	b := n.bridge
	now := time.Now()
	cands, err := b.store.Ed3kBridge(ctx, ed2k, limit*2, now)
	if err != nil || len(cands) == 0 {
		return nil
	}
	var out []BridgeSource
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, c := range cands {
		if len(out) >= limit {
			break
		}
		t := b.tested[c.EP4]
		if t != nil && !t.running && now.Sub(t.at) < b.ttl {
			if t.ok {
				out = append(out, BridgeSource{NodeID: c.NodeID, EP4: c.EP4})
			}
			continue
		}
		if t == nil || !t.running {
			b.start(c.EP4)
		}
	}
	b.listed.Add(uint64(len(out)))
	return out
}

func newBridge(store storage.Ed3kStore) *bridge {
	return &bridge{store: store, ttl: DefaultBridgeTestTTL, dial: tcpReachable,
		sem: make(chan struct{}, bridgeTests), tested: map[netip.AddrPort]*bridgeTest{}}
}

// start runs one TCP test in the background; b.mu is held.
func (b *bridge) start(ep netip.AddrPort) {
	select {
	case b.sem <- struct{}{}:
	default:
		return // enough tests running; a later request asks again
	}
	t := b.tested[ep]
	if t == nil {
		t = &bridgeTest{}
		b.tested[ep] = t
	}
	t.running = true
	go func() {
		defer func() { <-b.sem }()
		ctx, cancel := context.WithTimeout(context.Background(), bridgeDialTimeout)
		ok := b.dial(ctx, ep) == nil
		cancel()
		now := time.Now()
		b.mu.Lock()
		t.ok, t.at, t.running = ok, now, false
		for k, v := range b.tested {
			if !v.running && now.Sub(v.at) > 2*b.ttl {
				delete(b.tested, k)
			}
		}
		b.mu.Unlock()
	}()
}

func tcpReachable(ctx context.Context, ep netip.AddrPort) error {
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp4", ep.String())
	if err != nil {
		return err
	}
	return c.Close()
}
