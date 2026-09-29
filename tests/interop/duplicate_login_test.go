package interop

import (
	"net"
	"testing"
	"time"
)

// duplicateLoginHash is distinct from every other hash in this package, so this case never
// collides with a session another case holds open. Bytes 5 and 14 carry eMule's user-hash
// marks (14 and 111, srchybrid/Preferences.cpp CreateUserHash), so the hash looks like one
// a real eMule client would present.
var duplicateLoginHash = [16]byte{0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 14, 0xE6, 0xE7,
	0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 111, 0xEF}

// TestDuplicateLoginSameIP pins what each server does when a user hash that is already
// online logs in again from the same IP — the shape eMule's smart-LowID retry produces,
// since it abandons the first connection without closing it (srchybrid/ServerSocket.cpp:326-338)
// and reconnects before its own 25 s CONSERVTIMEOUT reaps the socket.
//
// The two servers deliberately differ here (docs/port-divergences.local.md, H1a):
//
//	eserver 17.14  keeps A and refuses every further LowID login from the IP — same hash
//	               or not, same client port or not
//	eNode-go       a same-hash login from the same IP replaces the live session; other
//	               hashes from the IP are separate sessions
//
// Every host→container connection in this rig arrives from the one Docker gateway address,
// so every login here is same-IP by construction, and none can get a HighID (the dial-back
// has no route to the host). The different-IP case cannot be built in this rig and is
// covered by ed2k/duplicate_login_test.go instead.
func TestDuplicateLoginSameIP(t *testing.T) {
	pool := requireInterop(t)

	t.Run("eserver", func(t *testing.T) {
		network := newNetwork(t, pool, false)
		eserver := startEserver(t, pool, network, eserverOptions{})
		out := observeDuplicateLogin(t, eserver.hostIP(), eserver.hostPort("4661/tcp"))
		if t.Failed() {
			t.Logf("output: eserver log tail:\n%s", tail(eserver.logs(), 40))
			return
		}
		if out.Second.Accepted {
			t.Errorf("eserver accepted a same-hash same-IP re-login (B); it refused it when measured")
		}
		if out.FirstDropped {
			t.Errorf("eserver dropped the live session A on a re-login; it kept it when measured")
		}
		for name, r := range map[string]loginResult{"C": out.Control, "D": out.ControlPort, "E": out.SecondOtherPort} {
			if r.Accepted {
				t.Errorf("eserver accepted login %s; it refused every further LowID login from the IP when measured", name)
			}
		}
	})

	t.Run("enode", func(t *testing.T) {
		network := newNetwork(t, pool, false)
		enode := startEnode(t, pool, network, enodeOptions{Name: "enode"})
		out := observeDuplicateLogin(t, enode.hostIP(), enode.hostPort("5555/tcp"))
		if t.Failed() {
			t.Logf("output: enode log tail:\n%s", tail(enode.logs(), 40))
			return
		}
		if !out.Second.Accepted {
			t.Errorf("same-hash same-IP re-login (B) was refused (messages %q); it must replace the stale session",
				out.Second.Messages)
		}
		if !out.FirstDropped {
			t.Errorf("the stale session A was not closed when B took over")
		}
		if !out.Control.Accepted || !out.ControlPort.Accepted {
			t.Errorf("a different hash from the same IP was refused (C=%t D=%t); only the same hash is a duplicate",
				out.Control.Accepted, out.ControlPort.Accepted)
		}
		if !out.SecondOtherPort.Accepted {
			t.Errorf("same-hash re-login on another client port (E) was refused (messages %q)", out.SecondOtherPort.Messages)
		}
		if !out.SecondDroppedByE {
			t.Errorf("session B was not closed when E took over")
		}
	})
}

// duplicateLoginOutcome is what one run of the scenario observed.
type duplicateLoginOutcome struct {
	First, Second loginResult
	// FirstDropped: the server closed A within 10 s of B's login.
	FirstDropped bool
	// Control is a different hash from the same IP and client port, separating "refused
	// for the hash" from "refused for the address".
	Control loginResult
	// ControlPort differs in hash and client port.
	ControlPort loginResult
	// SecondOtherPort repeats A's hash on another client port, after B.
	SecondOtherPort loginResult
	// SecondDroppedByE: the server closed B within 5 s of E's login. Only meaningful
	// when B was accepted.
	SecondDroppedByE bool
}

func observeDuplicateLogin(t *testing.T, hostIP, hostPort string) duplicateLoginOutcome {
	t.Helper()
	var out duplicateLoginOutcome

	// Login A is retried while the server answers with a bare reset and no frames. Docker
	// Desktop's port proxy accepts a connection before the process behind it listens, so
	// the readiness dial in startEserver can pass while eserver, still starting under qemu,
	// is not yet serving; a genuine refusal would repeat until the timeout and still fail.
	var first net.Conn
	waitFor(t, 90*time.Second, "server to answer login A", func() bool {
		if first != nil {
			_ = first.Close()
		}
		first, out.First = openLogin(t, hostIP, hostPort, duplicateLoginHash, 4662)
		if !out.First.Accepted && len(out.First.Frames) == 0 {
			t.Logf("output: login A got no frames yet (%v), retrying", out.First.Err)
			return false
		}
		return true
	})
	defer first.Close()
	t.Logf("input: login A hash=%x client port 4662", duplicateLoginHash)
	logLogin(t, "A", out.First)
	if !out.First.Accepted {
		t.Errorf("first login was not accepted, nothing to measure")
		return out
	}

	second, res := openLogin(t, hostIP, hostPort, duplicateLoginHash, 4662)
	defer second.Close()
	out.Second = res
	t.Logf("input: login B, same hash, same source IP and client port, while A is still open")
	logLogin(t, "B", out.Second)

	dropped, err := closedWithin(first, 10*time.Second)
	out.FirstDropped = dropped
	t.Logf("output: A dropped by server within 10s=%t (err=%v)", dropped, err)

	control := duplicateLoginHash
	control[0] ^= 0xFF
	third, res := openLogin(t, hostIP, hostPort, control, 4662)
	defer third.Close()
	out.Control = res
	t.Logf("input: login C, different hash %x, same source IP and client port", control)
	logLogin(t, "C", out.Control)

	control2 := duplicateLoginHash
	control2[1] ^= 0xFF
	fourth, res := openLogin(t, hostIP, hostPort, control2, 4663)
	defer fourth.Close()
	out.ControlPort = res
	t.Logf("input: login D, different hash %x, same source IP, client port 4663", control2)
	logLogin(t, "D", out.ControlPort)

	fifth, res := openLogin(t, hostIP, hostPort, duplicateLoginHash, 4664)
	defer fifth.Close()
	out.SecondOtherPort = res
	t.Logf("input: login E, same hash as A and B, same source IP, client port 4664")
	logLogin(t, "E", out.SecondOtherPort)

	if out.Second.Accepted {
		dropped, err = closedWithin(second, 5*time.Second)
		out.SecondDroppedByE = dropped
		t.Logf("output: B dropped by server within 5s of E=%t (err=%v)", dropped, err)
	}
	return out
}

func logLogin(t *testing.T, name string, r loginResult) {
	t.Helper()
	t.Logf("output: %s accepted=%t id=%d frames=%v messages=%q err=%v",
		name, r.Accepted, r.ID, r.Frames, r.Messages, r.Err)
}
