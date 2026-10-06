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

// TestPublicStatusMatchesStatusPackets pins that the HTTP status route's source
// reports the advertised figures, the boost included, never the real counts.
func TestPublicStatusMatchesStatusPackets(t *testing.T) {
	rt := NewServerRuntime(TCPRuntimeConfig{AllowLowIDs: true},
		UDPRuntimeConfig{Name: "eNode", Description: "test", MaxConnections: 1000, SoftFiles: 2000, HardFiles: 3000},
		fixedCountsEngine{Engine: storage.NewMemoryEngine(), clients: 4, files: 700})
	for i := 0; i < 2; i++ {
		if _, ok := rt.LowIDs.AddByEndpoint(uint32(0x0a000001+i), uint16(4662+i), i); !ok {
			t.Fatal("AddByEndpoint failed")
		}
	}
	boost := StatsBoost{Users: 40001, LowIDUsers: 1000, Files: 5000001}
	rt.SetStatsBoost(boost)

	packet, err := rt.buildStatRes(0x1122, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, b := payloadAfterOpcode(t, packet)
	udp, err := ParseGlobServStatRes(b)
	if err != nil {
		t.Fatal(err)
	}
	got := rt.PublicStatus()
	clients, files := rt.Counts()

	t.Logf("input: boost=%+v, real users=%d lowIDs=2 files=%d", boost, clients, files)
	t.Logf("output: PublicStatus=%+v; UDP users=%d lowIDs=%d files=%d", got, udp.Users, udp.LowIDUsers, udp.Files)
	if uint32(got.Users) != udp.Users || uint32(got.LowIDUsers) != udp.LowIDUsers || uint32(got.Files) != udp.Files {
		t.Fatalf("PublicStatus disagrees with OP_GLOBSERVSTATRES")
	}
	if got.Users != 40005 || got.LowIDUsers != 1002 || got.Files != 5000701 {
		t.Fatalf("PublicStatus counts: %+v", got)
	}
	if got.Name != "eNode" || got.Description != "test" || got.MaxUsers != 1000 || got.SoftFileLimit != 2000 || got.HardFileLimit != 3000 {
		t.Fatalf("PublicStatus identity and limits: %+v", got)
	}
}

// TestStatsBoostNetworkUsers pins the two network switches: off they add nothing even
// with estimates at hand, on each adds its own network's estimate to the users of
// both status packets and of PublicStatus alike, the sum saturates at uint32, and
// neither the LowID count nor the file count moves.
func TestStatsBoostNetworkUsers(t *testing.T) {
	estimates := map[string]int{metaNetworkKad: 412000, metaNetworkTorrent: 9000000}
	cases := []struct {
		name      string
		boost     StatsBoost
		users     map[string]int
		wantUsers uint32
	}{
		{"both off", StatsBoost{}, estimates, 4},
		{"offset only", StatsBoost{Users: 100}, estimates, 104},
		{"kad on", StatsBoost{KadUsers: true}, estimates, 412004},
		{"torrent on", StatsBoost{TorrentUsers: true}, estimates, 9000004},
		{"both on with offset", StatsBoost{Users: 100, KadUsers: true, TorrentUsers: true}, estimates, 9412104},
		{"on without an estimate", StatsBoost{KadUsers: true, TorrentUsers: true}, nil, 4},
		{"clamped to uint32", StatsBoost{Users: math.MaxUint32 - 10, KadUsers: true}, estimates, math.MaxUint32},
	}
	for _, tc := range cases {
		rt := NewServerRuntime(TCPRuntimeConfig{AllowLowIDs: true}, UDPRuntimeConfig{},
			fixedCountsEngine{Engine: storage.NewMemoryEngine(), clients: 4, files: 700})
		if _, ok := rt.LowIDs.AddByEndpoint(0x0a000001, 4662, 0); !ok {
			t.Fatal("AddByEndpoint failed")
		}
		rt.SetMetaSearcher(&fakeMeta{users: tc.users}, true)
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
		public := rt.PublicStatus()

		t.Logf("input: %s, boost=%+v, estimates=%v, real users=4 lowIDs=1 files=700", tc.name, tc.boost, tc.users)
		t.Logf("output: UDP users=%d lowIDs=%d files=%d; TCP users=%d files=%d; status users=%d",
			udp.Users, udp.LowIDUsers, udp.Files, tcpUsers, tcpFiles, public.Users)

		if udp.Users != tc.wantUsers || tcpUsers != tc.wantUsers || uint32(public.Users) != tc.wantUsers {
			t.Errorf("%s: users udp=%d tcp=%d status=%d, want %d", tc.name, udp.Users, tcpUsers, public.Users, tc.wantUsers)
		}
		if udp.LowIDUsers != 1 || public.LowIDUsers != 1 {
			t.Errorf("%s: lowIDs udp=%d status=%d, want the real 1", tc.name, udp.LowIDUsers, public.LowIDUsers)
		}
		if udp.Files != 700 || tcpFiles != 700 || public.Files != 700 {
			t.Errorf("%s: files udp=%d tcp=%d status=%d, want the real 700", tc.name, udp.Files, tcpFiles, public.Files)
		}
	}
}

// TestStatsBoostNetworkUsersWithoutMeta: a switch set on a server with no meta
// searcher attached advertises the real count.
func TestStatsBoostNetworkUsersWithoutMeta(t *testing.T) {
	rt := NewServerRuntime(TCPRuntimeConfig{}, UDPRuntimeConfig{},
		fixedCountsEngine{Engine: storage.NewMemoryEngine(), clients: 4, files: 700})
	boost := StatsBoost{KadUsers: true, TorrentUsers: true}
	rt.SetStatsBoost(boost)
	got := rt.PublicStatus().Users
	t.Logf("input: boost=%+v, no meta searcher, real users=4", boost)
	t.Logf("output: advertised users=%d", got)
	if got != 4 {
		t.Fatalf("users=%d, want 4", got)
	}
}

// TestStatsBoostNetworkUsersReload: a reload that flips a switch takes effect on the
// next status reply, with the listeners live.
func TestStatsBoostNetworkUsersReload(t *testing.T) {
	rt := NewServerRuntime(TCPRuntimeConfig{}, UDPRuntimeConfig{},
		fixedCountsEngine{Engine: storage.NewMemoryEngine(), clients: 4, files: 700})
	rt.SetMetaSearcher(&fakeMeta{users: map[string]int{metaNetworkKad: 412000}}, true)

	before := rt.PublicStatus().Users
	rt.SetStatsBoost(StatsBoost{KadUsers: true})
	on := rt.PublicStatus().Users
	rt.SetStatsBoost(StatsBoost{})
	off := rt.PublicStatus().Users

	t.Logf("input: kad estimate 412000, real users=4; kadUsers off, on, off again")
	t.Logf("output: users=%d, %d, %d", before, on, off)
	if before != 4 || on != 412004 || off != 4 {
		t.Fatalf("users=%d/%d/%d, want 4/412004/4", before, on, off)
	}
}
