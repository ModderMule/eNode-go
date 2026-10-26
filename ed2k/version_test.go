package ed2k

import (
	"fmt"
	"strings"
	"testing"
)

// TestLoginVersionStr pins the text after "server version " in the TCP login line. eMule
// shows it in the server list's Version column in place of the UDP ST_VERSION, so it
// must name us and still carry the compatibility claim. srchybrid tries
// _stscanf("%u.%u") on it first and, if that succeeds, shows only "%u.%02u"
// (ServerSocket.cpp:180-181), so it must not open with a number.
func TestLoginVersionStr(t *testing.T) {
	t.Logf("input: ENodeName=%q ENodeVersionStr=%q GossipCompatVersion=%q",
		ENodeName, ENodeVersionStr, GossipCompatVersion)
	t.Logf("output: LoginVersionStr = %q", LoginVersionStr)

	want := fmt.Sprintf("%s %s (%s)", ENodeName, ENodeVersionStr, GossipCompatVersion)
	if LoginVersionStr != want {
		t.Errorf("LoginVersionStr is %q, want %q", LoginVersionStr, want)
	}

	var major, minor uint
	if n, _ := fmt.Sscanf(strings.TrimSpace(LoginVersionStr), "%d.%d", &major, &minor); n == 2 {
		t.Errorf("LoginVersionStr %q parses as %d.%d, so srchybrid would display a bare version "+
			"and drop our name", LoginVersionStr, major, minor)
	}
}
