package ed2k

import (
	"net"
	"testing"

	"enode/storage"
)

// stubSpam records what the offer handler hands a SpamObserver.
type stubSpam struct {
	calls    int
	sessions []any
	files    []storage.File
	userHash []byte
}

func (s *stubSpam) ObserveOffer(session any, userHash []byte, _ net.IP, files []storage.File) any {
	s.calls++
	s.sessions = append(s.sessions, session)
	s.files = append(s.files, files...)
	s.userHash = append([]byte(nil), userHash...)
	return "session-state"
}

// TestOfferFilesReachTheSpamObserver: the observer sees the files the content filter
// let through, including those past the soft limit, gets its own session state back
// on the next offer, and changes nothing about what is indexed.
func TestOfferFilesReachTheSpamObserver(t *testing.T) {
	engine := storage.NewMemoryEngine()
	client, conn := newOfferLimitClient(t, engine, 3, 0)
	spam := &stubSpam{}
	client.server.SetSpamObserver(spam)
	client.server.SetContentFilter(&stubContent{filtered: hashSet(offerHash(1))})

	offerFiles(t, client, 0, 5) // #1 is refused by the content filter; the soft limit is 3
	offerFiles(t, client, 5, 1)
	t.Logf("input: OP_OFFERFILES of 5 files (#1 on the filter list, soft limit 3), then 1 more")
	t.Logf("output: calls=%d observed=%d sessions=%v userHash=%x FilesCount=%d closed=%d",
		spam.calls, len(spam.files), spam.sessions, spam.userHash, engine.FilesCount(), conn.closed)

	if spam.calls != 2 || len(spam.files) != 5 {
		t.Fatalf("calls=%d observed=%d, want 2 calls and 5 files: every accepted record, before the soft limit", spam.calls, len(spam.files))
	}
	for _, f := range spam.files {
		if string(f.Hash) == string(offerHash(1)) {
			t.Error("a file the content filter refused reached the observer")
		}
	}
	if spam.sessions[0] != nil || spam.sessions[1] != "session-state" {
		t.Errorf("sessions = %v, want nil first and then what the observer returned", spam.sessions)
	}
	if len(spam.userHash) != 16 || spam.userHash[0] != 0x5a {
		t.Errorf("userHash = %x, want the session's", spam.userHash)
	}
	if engine.FilesCount() != 3 || conn.closed != 0 {
		t.Errorf("FilesCount=%d closed=%d, want 3 and an open session: observing changes nothing", engine.FilesCount(), conn.closed)
	}
}
