package ed2k

import (
	"encoding/binary"
	"math"
	"net"
	"testing"
	"time"

	"enode/storage"
)

// fixedCountsEngine reports fixed client and file counts, so a status test can tell
// the real share of an advertised figure from the statsBoost share.
type fixedCountsEngine struct {
	storage.Engine
	clients, files int
}

func (e fixedCountsEngine) ClientsCount() int { return e.clients }
func (e fixedCountsEngine) FilesCount() int   { return e.files }

// TestStatsBoostAppliedToTCPAndUDP pins that the configured offsets reach both
// status packets identically, that no boost advertises the real counts (the old
// hard-coded +2000/+1000 is gone), and that a huge offset saturates at uint32.
func TestStatsBoostAppliedToTCPAndUDP(t *testing.T) {
	cases := []struct {
		name                             string
		boost                            StatsBoost
		wantUsers, wantLowIDs, wantFiles uint32
	}{
		{"no boost: real counts", StatsBoost{}, 4, 2, 700},
		{"eMule auto-search thresholds", StatsBoost{Users: 40001, LowIDUsers: 1000, Files: 5000001}, 40005, 1002, 5000701},
		{"clamped to uint32", StatsBoost{Users: math.MaxUint32, LowIDUsers: math.MaxUint32, Files: math.MaxUint32},
			math.MaxUint32, math.MaxUint32, math.MaxUint32},
	}
	for _, tc := range cases {
		rt := NewServerRuntime(TCPRuntimeConfig{AllowLowIDs: true}, UDPRuntimeConfig{},
			fixedCountsEngine{Engine: storage.NewMemoryEngine(), clients: 4, files: 700})
		for i := 0; i < 2; i++ {
			if _, ok := rt.LowIDs.AddByEndpoint(uint32(0x0a000001+i), uint16(4662+i), i); !ok {
				t.Fatal("AddByEndpoint failed")
			}
		}
		rt.SetStatsBoost(tc.boost)

		packet, err := rt.buildStatRes(0x1122, 0, nil)
		if err != nil {
			t.Fatal(err)
		}
		_, b := payloadAfterOpcode(t, packet)
		udp, err := ParseGlobServStatRes(b)
		if err != nil {
			t.Fatal(err)
		}
		tcpUsers, tcpFiles := readServerStatusCounts(t, rt)

		t.Logf("input: %s, boost=%+v, real users=4 lowIDs=2 files=700", tc.name, tc.boost)
		t.Logf("output: UDP users=%d lowIDs=%d files=%d; TCP users=%d files=%d",
			udp.Users, udp.LowIDUsers, udp.Files, tcpUsers, tcpFiles)

		if udp.Users != tc.wantUsers || tcpUsers != tc.wantUsers {
			t.Errorf("%s: users udp=%d tcp=%d, want %d", tc.name, udp.Users, tcpUsers, tc.wantUsers)
		}
		if udp.Files != tc.wantFiles || tcpFiles != tc.wantFiles {
			t.Errorf("%s: files udp=%d tcp=%d, want %d", tc.name, udp.Files, tcpFiles, tc.wantFiles)
		}
		if udp.LowIDUsers != tc.wantLowIDs {
			t.Errorf("%s: lowIDs udp=%d, want %d", tc.name, udp.LowIDUsers, tc.wantLowIDs)
		}
	}
}

// readServerStatusCounts sends one OP_SERVERSTATUS over a pipe and returns its
// users and files fields.
func readServerStatusCounts(t *testing.T, rt *ServerRuntime) (users, files uint32) {
	t.Helper()
	server, client := net.Pipe()
	defer client.Close()
	c := newTCPClient(rt, server, false)
	got := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 64)
		_ = client.SetReadDeadline(time.Now().Add(time.Second))
		n, _ := client.Read(buf)
		got <- buf[:n]
	}()
	c.sendServerStatus()
	server.Close()
	raw := <-got
	// protocol, uint32 length, opcode, users, files
	if len(raw) < 14 || raw[5] != OpServerStatus {
		t.Fatalf("not an OP_SERVERSTATUS: % x", raw)
	}
	return binary.LittleEndian.Uint32(raw[6:10]), binary.LittleEndian.Uint32(raw[10:14])
}
