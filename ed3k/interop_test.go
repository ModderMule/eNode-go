package ed3k

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"enode/storage"
)

// TestPackmuleDialsNode starts this index node and a packmule-node (the Rust
// reference) that bootstraps from it: rustls dials this node's RFC 7250 server
// through the obfuscating socket, and its Hello and KadRequest are answered.
// packmule publishes only through Kad ROUTERs and has no index-client option
// (docs/ed3k-index-node.md), so its --share does not reach a node without ROUTER;
// the test reports what it published. Opt-in: set ENODE_ED3K_PACKMULE to the
// packmule-node binary.
func TestPackmuleDialsNode(t *testing.T) {
	bin := os.Getenv("ENODE_ED3K_PACKMULE")
	if bin == "" {
		t.Skip("set ENODE_ED3K_PACKMULE to a packmule-node binary")
	}
	const network = "enode interop"
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	store := storage.NewMemoryEngine()
	n, err := New(Config{Key: priv, Listen: netip.MustParseAddrPort("127.0.0.1:0"), Network: network,
		Agent: "eNode-go interop", Store: store})
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	n.cfg.Advertise4 = netip.MustParseAddrPort(n.LocalAddr().String())
	link := n.Link().String()
	t.Logf("eNode-go index node: %s", link)

	dir := t.TempDir()
	file := filepath.Join(dir, "Interop.Test.Movie.1946.mkv")
	data := make([]byte, 300_000)
	rand.Read(data)
	os.WriteFile(file, data, 0o644)
	cmd := exec.Command(bin, "--port", "0", "--bind", "127.0.0.1", "--network", network, "--force-open",
		"--lan", "off", "--key", filepath.Join(dir, "pm.key"), "--bootstrap", link, "--share", file)
	out, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	go func() {
		sc := bufio.NewScanner(stderr)
		for sc.Scan() {
			t.Logf("packmule: %s", sc.Text())
		}
	}()
	go func() {
		sc := bufio.NewScanner(out)
		for sc.Scan() {
			t.Logf("packmule stdout: %s", sc.Text())
		}
	}()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		st, _ := store.Ed3kStats(context.Background(), time.Now())
		if n.Stats().Exchanges >= 2 && st.Sources > 0 && st.Keywords > 0 {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	st, _ := store.Ed3kStats(context.Background(), time.Now())
	ns := n.Stats()
	t.Logf("node: accepted=%d exchanges=%d index=%+v; store=%+v obfs dropped=%d", ns.Accepted, ns.Exchanges, ns.Index, st, ns.ObfsDropped)
	if ns.Accepted == 0 || ns.Exchanges < 2 || ns.Refused != 0 {
		t.Fatal("packmule did not connect and exchange Hello and a KadRequest")
	}
	if st.Sources == 0 || st.Keywords == 0 {
		t.Logf("packmule published nothing here: it stores through Kad ROUTERs only (known, not a failure)")
	}
}
