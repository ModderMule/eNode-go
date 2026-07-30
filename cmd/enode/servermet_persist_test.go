package main

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"enode/ed2k"
)

// verifiedHandler returns a handler holding one advertisable peer, so
// VerifiedEntries has something to write. A seed enters at peerSeen, which is below
// the advertisable bar; NoteDescription is the promotion the real code reaches via
// an OP_SERVERDESCRES reply.
func verifiedHandler(t *testing.T) *ed2k.GossipHandler {
	t.Helper()
	peer := net.ParseIP("192.0.2.10")
	handler := ed2k.NewGossipHandler(ed2k.GossipConfig{
		SelfIPv4:    net.ParseIP("198.51.100.1"),
		SelfPort:    4661,
		MaxServers:  16,
		MaxFailures: 3,
	}, []ed2k.PeerAddr{{IP: peer, Port: 4661}})
	if !handler.NoteDescription(peer, "peer one", "a peer") {
		t.Fatal("could not promote the seed to an advertisable state")
	}
	if n := len(handler.VerifiedEntries()); n != 1 {
		t.Fatalf("want 1 verified entry to persist, got %d", n)
	}
	return handler
}

// The stopper must not return until the final write has finished. It used to only
// close the done channel, so main's remaining defers ran and the process could exit
// while WriteServerMet was still writing — losing the shutdown flush and leaving the
// temp file behind. server.met is small enough that the old code usually won this
// race, which is precisely why it survived: the failure was intermittent.
//
// The interval is an hour, so only the stop path can produce this file, and nothing
// here polls for it: existing the instant stop() returns is the invariant.
func TestServerMetPersistenceFlushesBeforeStopperReturns(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.met")
	handler := verifiedHandler(t)

	stop := startServerMetPersistence(context.Background(), path, time.Hour, handler)
	if _, err := os.Stat(path); err == nil {
		t.Fatal("nothing should have been written before the first tick")
	}
	t.Logf("input:  startServerMetPersistence(%s, every=1h), 1 verified peer, stopping immediately", path)

	stop()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("the stopper returned before the shutdown write landed: %v", err)
	}
	entries, err := ed2k.ReadServerMet(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	t.Logf("output: %d byte(s) on disk, %d entry(ies) read back", info.Size(), len(entries))
	if len(entries) != 1 {
		t.Fatalf("want 1 persisted peer, got %d", len(entries))
	}
	if entries[0].Port != 4661 || !entries[0].IP.Equal(net.ParseIP("192.0.2.10")) {
		t.Fatalf("wrong peer persisted: %s:%d", entries[0].IP, entries[0].Port)
	}

	// Registered with defer alongside the other stoppers, so a second call must
	// neither panic on a closed channel nor block on the already-closed goroutine.
	done := make(chan struct{})
	go func() { defer close(done); stop() }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("a second stop() blocked — the stopper is not idempotent")
	}
}

// Cancelling the context also writes and exits the goroutine. The stopper is still
// called afterwards by the defer in startGossipLoops, and must return rather than
// wait forever on a goroutine that has already finished.
func TestServerMetPersistenceStopperReturnsAfterContextCancel(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.met")
	handler := verifiedHandler(t)

	ctx, cancel := context.WithCancel(context.Background())
	stop := startServerMetPersistence(ctx, path, time.Hour, handler)
	cancel()

	// The context path is asynchronous — unlike stop(), nothing waits on it — so
	// this one does have to wait for the write.
	deadline := time.Now().Add(5 * time.Second)
	var statErr error
	for time.Now().Before(deadline) {
		if _, statErr = os.Stat(path); statErr == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Logf("input:  context cancelled with a 1h interval")
	t.Logf("output: server.met present=%t", statErr == nil)
	if statErr != nil {
		t.Fatalf("cancelling the context must still flush: %v", statErr)
	}

	done := make(chan struct{})
	go func() { defer close(done); stop() }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("stop() blocked after the goroutine had already exited via ctx.Done()")
	}
}
