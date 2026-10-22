package transport

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"enode/ed3k/ed3kpb"
	"enode/ed3k/ident"
	"enode/ed3k/obfs"
	"enode/ed3k/wire"
)

// TestPackmuleHello dials the Rust reference node (packmule-node) through the
// obfuscating socket with RFC 7250 keys and exchanges Hello. Opt-in: set
// ENODE_ED3K_PACKMULE to the packmule-node binary.
func TestPackmuleHello(t *testing.T) {
	bin := os.Getenv("ENODE_ED3K_PACKMULE")
	if bin == "" {
		t.Skip("set ENODE_ED3K_PACKMULE to a packmule-node binary")
	}
	const network = "enode interop"
	dir := t.TempDir()
	cmd := exec.Command(bin, "--port", "0", "--bind", "127.0.0.1", "--network", network,
		"--force-open", "--index", "--lan", "off", "--key", filepath.Join(dir, "pm.key"))
	out, _ := cmd.StdoutPipe()
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	var link ident.NodeLink
	sc := bufio.NewScanner(out)
	for sc.Scan() {
		if l, ok := strings.CutPrefix(sc.Text(), "node "); ok {
			var err error
			if link, err = ident.ParseNodeLink(l, true); err != nil {
				t.Fatalf("link %q: %v", l, err)
			}
			break
		}
	}
	t.Logf("packmule node: %s", link)

	_, cpriv, _ := ed25519.GenerateKey(rand.Reader)
	udp, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	pc := obfs.NewClient(udp, obfs.NetID(network), link.ID.Obf())
	defer pc.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	c, err := Dial(ctx, pc, net.UDPAddrFromAddrPort(link.EP4), cpriv, link.ID, QUICConfig(IdleIndex))
	if err != nil {
		t.Fatalf("dial packmule: %v", err)
	}
	defer c.CloseWithError(CodeClosed, "")
	s, err := c.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := wire.WriteFrame(s, wire.TypeHello, &ed3kpb.Hello{Caps: 1 << 6, Agent: "eNode-go interop"}); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s.SetReadDeadline(time.Now().Add(10 * time.Second))
	f, err := wire.ReadFrame(wire.NewReader(s))
	if err != nil || f.Type != wire.TypeHello {
		t.Fatalf("hello answer: type %d err %v", f.Type, err)
	}
	var h ed3kpb.Hello
	if err := protoUnmarshal(f.Body, &h); err != nil {
		t.Fatal(err)
	}
	obs, _, _ := ident.DecodeEndpoint(h.Observed)
	t.Logf("packmule hello: caps=%#x agent=%q observed=%v nat=%d", h.Caps, h.Agent, obs, h.Nat)
	if obs.Port() != uint16(udp.LocalAddr().(*net.UDPAddr).Port) {
		t.Errorf("observed %v, our socket %v", obs, udp.LocalAddr())
	}
	t.Logf("obfs: dropped=%d", pc.Dropped.Load())
}
