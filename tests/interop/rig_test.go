// Package interop holds the Docker-backed interoperability suite: eNode-go and the
// original Lugdunum eserver 17.14 binary on one user-defined network, so the
// server-to-server gossip handshake can be verified in both directions against ground
// truth rather than against a reimplementation.
//
// It exists because of a rig limitation, not a protocol one. With eserver in a container
// and eNode-go on the host, the container has no route back — UDP and TCP to
// 192.168.65.1, 192.168.65.254 and host.docker.internal are all unreachable on Docker
// Desktop — so the real binary could never probe us, never reached our name:desc phase,
// and never entered us in its own server.met. On a shared network both directions are
// routable. See docs/interop-docker-tests.md.
//
// Gated on ENODE_INTEGRATION=1, matching the rest of the suite, and skipped when the
// gitignored lugdunum-eserver/ tree is absent.
package interop

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"enode/ed2k"
	"enode/tests"

	"github.com/ory/dockertest/v3"
	dc "github.com/ory/dockertest/v3/docker"
)

const (
	// TEST-NET-3 (RFC 5737). Chosen over Docker's default 172.17/172.18 pool for two
	// reasons. It keeps gossip.allowPrivatePeers at its production default of false —
	// 172.16/12 is LAN under ed2k.IsLANIP, so the default pool would force the escape
	// hatch on and the tests would exercise a path no real server runs. And eserver's own
	// conf/ipfilter.srv blocks 172.16.0.0/10 and 192.0.2.0/24 but not this range, so a
	// future run with that filter loaded will not silently deny the peer.
	interopSubnet4 = "203.0.113.0/24"
	interopGateway = "203.0.113.1"

	// 2001:db8::/32 (RFC 3849). A ULA would fail ed2k.IsPublicIPv6 — Go's IsPrivate
	// covers fc00::/7 — so the server would refuse to advertise an IPv6 at all and the
	// 0xA7/0xA8 extension could not be exercised. The documentation prefix is global
	// unicast and not private, so it passes.
	interopSubnet6 = "2001:db8:4661::/64"

	eserverTCPPort = 4661
	enodeTCPPort   = 5555
	// The obfuscation ports eNode publishes in its 0x97, which eserver echoes back in its
	// `vs` table as {U…} and {T…}. portUDPOBF is tcp+12 and shares the client obfuscated
	// socket — see config.setDefaults for why tcp+14 cannot be used.
	enodeUDPObfPort = 5567
	enodeTCPObfPort = 5565

	enodeImage   = "enode-interop:test"
	eserverImage = "lugdunum-interop:17.14-i686"

	// Docker Engine 20.10 and later. Anything below 1.40 is rejected outright by current
	// Docker Desktop; 1.41 is old enough to be present everywhere that still runs.
	dockerAPIVersion = "1.41"

	// Relative to the module root; gitignored, so a fresh clone will not have it.
	eserverBinaryPath = "lugdunum-eserver/run/eserver-17.14.i686-linux.nptl"
)

var (
	enodeImageOnce    sync.Once
	enodeImageErr     error
	eserverImageOnce  sync.Once
	eserverImageErr   error
	containerSeqMu    sync.Mutex
	containerSequence int
)

// liveStats mirrors admin.LiveStats' wire form. Declared here rather than imported so the
// test reads the JSON exactly as an external consumer would: if a field is renamed, this
// fails, which is the point (admin/server_test.go pins the same key names).
type liveStats struct {
	Clients          int    `json:"clients"`
	Servers          int    `json:"servers"`
	GossipKnown      int    `json:"gossipKnown"`
	GossipVerified   int    `json:"gossipVerified"`
	GossipParked     int    `json:"gossipParked"`
	GossipAdmitted   uint64 `json:"gossipAdmitted"`
	FilterBlockedIP  int64  `json:"filterBlockedIP"`
	FilterBlockedGeo int64  `json:"filterBlockedGeo"`
}

func (s liveStats) String() string {
	return fmt.Sprintf("servers=%d gossip{known=%d verified=%d parked=%d admitted=%d} filter{ip=%d geo=%d}",
		s.Servers, s.GossipKnown, s.GossipVerified, s.GossipParked, s.GossipAdmitted,
		s.FilterBlockedIP, s.FilterBlockedGeo)
}

// node is a running container on the interop network.
type node struct {
	t        *testing.T
	pool     *dockertest.Pool
	resource *dockertest.Resource
	label    string
	ip       string
	ip6      string
}

// requireInterop applies both gates and returns a pool. The Docker check is a Skip, not a
// Fatal: a developer without Docker running should see the suite step aside, exactly as
// storage/integration_dockertest_test.go does.
func requireInterop(t *testing.T) *dockertest.Pool {
	t.Helper()
	if os.Getenv("ENODE_INTEGRATION") != "1" {
		t.Skip("set ENODE_INTEGRATION=1 to run integration tests")
	}
	endpoint := dockerEndpoint()

	// A versioned client, built directly rather than via dockertest.NewPool, which is only
	// `&Pool{Client: dc.NewClient(endpoint)}`. Its unversioned NewClient negotiates API
	// 1.25, and current Docker Desktop refuses anything below 1.40 — but only for some
	// calls: /_ping answers happily at 1.25 and then BuildImage fails with "client version
	// 1.25 is too old". Pinning the version up front turns that into a clear skip instead of
	// a confusing mid-test failure.
	client, err := dc.NewVersionedClient(endpoint, dockerAPIVersion)
	if err != nil {
		t.Skipf("docker not available (endpoint %q): %v", orDefaultSocket(endpoint), err)
	}
	pool := &dockertest.Pool{Client: client, MaxWait: 3 * time.Minute}
	if err := pool.Client.Ping(); err != nil {
		t.Skipf("docker daemon not responding (endpoint %q): %v", orDefaultSocket(endpoint), err)
	}
	t.Logf("input: docker endpoint %s (API %s)", orDefaultSocket(endpoint), dockerAPIVersion)
	return pool
}

// dockerEndpoint finds the daemon socket. dockertest defaults to /var/run/docker.sock and
// does not read Docker CLI contexts, so on Docker Desktop for macOS — where the socket
// lives under $HOME/.docker/run and /var/run/docker.sock does not exist at all — the
// default fails even though `docker ps` works fine. An explicit DOCKER_HOST always wins;
// otherwise the known per-runtime locations are tried before giving up and letting
// dockertest use its default (so the skip message names the real problem).
func dockerEndpoint() string {
	if h := os.Getenv("DOCKER_HOST"); h != "" {
		return h
	}
	if _, err := os.Stat("/var/run/docker.sock"); err == nil {
		return ""
	}
	home, _ := os.UserHomeDir()
	candidates := []string{
		filepath.Join(home, ".docker", "run", "docker.sock"),     // Docker Desktop
		filepath.Join(home, ".colima", "default", "docker.sock"), // Colima
		filepath.Join(home, ".rd", "docker.sock"),                // Rancher Desktop
	}
	if runtimeDir := os.Getenv("XDG_RUNTIME_DIR"); runtimeDir != "" {
		candidates = append(candidates, filepath.Join(runtimeDir, "docker.sock")) // rootless Linux
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return "unix://" + c
		}
	}
	return ""
}

func orDefaultSocket(endpoint string) string {
	if endpoint == "" {
		return "unix:///var/run/docker.sock (dockertest default)"
	}
	return endpoint
}

// eserverBinary resolves the vendored 32-bit ELF, skipping when the tree is absent.
func eserverBinary(t *testing.T) string {
	t.Helper()
	path := tests.FixRelativeTestingPath(eserverBinaryPath)
	if _, err := os.Stat(path); err != nil {
		t.Skipf("Lugdunum reference binary not present at %s (the tree is gitignored): %v",
			eserverBinaryPath, err)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		t.Fatalf("resolve %s: %v", path, err)
	}
	return abs
}

// moduleRoot is the directory holding go.mod — the build context for the eNode image,
// which needs the whole module.
func moduleRoot(t *testing.T) string {
	t.Helper()
	abs, err := filepath.Abs(tests.FixRelativeTestingPath("go.mod"))
	if err != nil {
		t.Fatalf("resolve module root: %v", err)
	}
	return filepath.Dir(abs)
}

// newNetwork creates a private bridge with a pinned subnet and removes it on cleanup.
//
// The subnet is pinned rather than left to Docker because the whole rig depends on which
// range the containers land in: TEST-NET-3 is what keeps allowPrivatePeers false.
func newNetwork(t *testing.T, pool *dockertest.Pool, dualStack bool) *dockertest.Network {
	t.Helper()
	name := fmt.Sprintf("enode-interop-%s-%d", sanitize(t.Name()), time.Now().UnixNano())
	ipam := &dc.IPAMOptions{
		Driver: "default",
		Config: []dc.IPAMConfig{{Subnet: interopSubnet4, Gateway: interopGateway}},
	}
	if dualStack {
		ipam.Config = append(ipam.Config, dc.IPAMConfig{Subnet: interopSubnet6})
	}
	net, err := pool.CreateNetwork(name, func(cfg *dc.CreateNetworkOptions) {
		cfg.Driver = "bridge"
		cfg.IPAM = ipam
		cfg.EnableIPv6 = dualStack
	})
	if err != nil {
		t.Fatalf("create network %s (subnet %s, dualStack=%v): %v", name, interopSubnet4, dualStack, err)
	}
	// Registered before any container, so LIFO cleanup purges the containers first —
	// removing a network with attached endpoints fails.
	t.Cleanup(func() { _ = net.Close() })
	t.Logf("input: network %s subnet=%s dualStack=%v", name, interopSubnet4, dualStack)
	return net
}

// eserverOptions configures a reference-server container.
type eserverOptions struct {
	// SeedIP/SeedPort populate donkey.ini's seedIP/seedPort, so eserver bootstraps a peer
	// list from that address on startup.
	SeedIP   string
	SeedPort int
	// IPFilter is written to ipfilter.srv in eserver's own netmask format.
	IPFilter string
}

// startEserver builds (once) and runs the reference server, waiting until its client TCP
// port accepts a connection.
func startEserver(t *testing.T, pool *dockertest.Pool, network *dockertest.Network, opts eserverOptions) *node {
	t.Helper()
	binary := eserverBinary(t)

	eserverImageOnce.Do(func() { eserverImageErr = buildEserverImage(t, pool, binary) })
	if eserverImageErr != nil {
		t.Fatalf("build %s: %v", eserverImage, eserverImageErr)
	}

	env := []string{"THIS_IP=auto"}
	if opts.SeedIP != "" {
		port := opts.SeedPort
		if port == 0 {
			port = enodeTCPPort
		}
		env = append(env, "SEED_IP="+opts.SeedIP, fmt.Sprintf("SEED_PORT=%d", port))
	}
	if opts.IPFilter != "" {
		env = append(env, "IPFILTER="+opts.IPFilter)
	}

	n := runContainer(t, pool, network, "eserver", eserverImage, env, []string{
		"4661/tcp", "4661/udp", "4665/udp", "4669/udp", "4673/udp", "4675/udp",
	})

	// eserver binds its client listener last, so a successful dial means the UDP sockets
	// are up too. Under qemu-i386 startup takes a few seconds.
	if err := pool.Retry(func() error {
		c, err := net.DialTimeout("tcp", net.JoinHostPort(n.hostIP(), n.hostPort("4661/tcp")), 2*time.Second)
		if err != nil {
			return err
		}
		return c.Close()
	}); err != nil {
		t.Fatalf("eserver never accepted a TCP connection: %v\nlogs:\n%s", err, n.logs())
	}
	t.Logf("output: eserver up at %s:%d (host tcp %s)", n.ip, eserverTCPPort, n.hostPort("4661/tcp"))
	return n
}

// enodeOptions configures an eNode-go container.
type enodeOptions struct {
	Name string
	// SeedIP/SeedPort become the single entry of gossip.seeds. Empty means no seeds, which
	// is how the first node of a pair starts.
	SeedIP   string
	SeedPort int
	// IPFilter is written to ipfilter.dat and switches filter.ipfilter.enabled to true.
	IPFilter string
}

// startEnode builds (once) and runs an eNode-go container, waiting until /stats.json
// answers — which also proves the config rendered and every listener bound.
func startEnode(t *testing.T, pool *dockertest.Pool, network *dockertest.Network, opts enodeOptions) *node {
	t.Helper()
	enodeImageOnce.Do(func() { enodeImageErr = buildEnodeImage(t, pool) })
	if enodeImageErr != nil {
		t.Fatalf("build %s: %v", enodeImage, enodeImageErr)
	}

	label := opts.Name
	if label == "" {
		label = "enode"
	}
	env := []string{"ENODE_NAME=" + label}
	if opts.SeedIP != "" {
		port := opts.SeedPort
		if port == 0 {
			port = eserverTCPPort
		}
		env = append(env, "SEED_IP="+opts.SeedIP, fmt.Sprintf("SEED_PORT=%d", port))
	}
	if opts.IPFilter != "" {
		env = append(env, "IPFILTER="+opts.IPFilter)
	}

	n := runContainer(t, pool, network, label, enodeImage, env, []string{
		"5555/tcp", "5565/tcp", "4560/tcp", "5559/udp", "5567/udp", "5569/udp",
	})

	if err := pool.Retry(func() error {
		_, err := n.stats()
		return err
	}); err != nil {
		t.Fatalf("%s never served /stats.json: %v\nlogs:\n%s", label, err, n.logs())
	}
	t.Logf("output: %s up at %s:%d (admin http %s:%s)", label, n.ip, enodeTCPPort, n.hostIP(), n.hostPort("4560/tcp"))
	return n
}

// stats fetches and decodes /stats.json from the published admin port.
func (n *node) stats() (liveStats, error) {
	var out liveStats
	url := fmt.Sprintf("http://%s:%s/stats.json", n.hostIP(), n.hostPort("4560/tcp"))
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return out, fmt.Errorf("GET %s: status %d", url, resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return out, fmt.Errorf("decode %s: %w", url, err)
	}
	return out, nil
}

// console writes a command to eserver's console FIFO. Replies appear on stdout, so they
// are read back through logs().
func (n *node) console(cmd string) {
	n.t.Helper()
	code, err := n.resource.Exec(
		[]string{"sh", "-c", fmt.Sprintf("printf '%%s\\n' %q > /rig/console", cmd)},
		dockertest.ExecOptions{},
	)
	if err != nil || code != 0 {
		n.t.Fatalf("%s: console %q failed: exit=%d err=%v", n.label, cmd, code, err)
	}
	n.t.Logf("input: %s console <- %q", n.label, cmd)
	// The console is a separate thread from the UDP workers; give it a moment to run the
	// command and flush its output before a caller reads the logs.
	time.Sleep(1500 * time.Millisecond)
}

// restart stops and starts the container in place, keeping its filesystem and its address
// on the network. Used to prove that state written to disk — data/server.met — is read back
// on the next boot; recreating the container instead would take the file with it.
//
// Note that logs() after this returns the *new* process's output only, since Docker resets
// the stream on restart. That is what makes "seed(s) from data/server.met" a meaningful
// assertion rather than a match against the previous boot.
func (n *node) restart(t *testing.T) {
	t.Helper()
	id := n.resource.Container.ID
	if err := n.pool.Client.RestartContainer(id, 10); err != nil {
		t.Fatalf("restart %s: %v", n.label, err)
	}
	// Re-inspect: with PublishAllPorts, Docker assigns a *new* ephemeral host port on every
	// start, so the cached Container snapshot still names the old one and every subsequent
	// stats() would dial a closed port.
	container, err := n.pool.Client.InspectContainer(id)
	if err != nil {
		t.Fatalf("re-inspect %s after restart: %v", n.label, err)
	}
	n.resource.Container = container

	if err := n.pool.Retry(func() error {
		_, err := n.stats()
		return err
	}); err != nil {
		t.Fatalf("%s did not come back after a restart: %v\nlogs:\n%s", n.label, err, n.logs())
	}
	t.Logf("output: %s restarted and serving again at %s", n.label, n.ip)
}

// logs returns everything the container has written to stdout and stderr.
func (n *node) logs() string {
	var buf bytes.Buffer
	err := n.pool.Client.Logs(dc.LogsOptions{
		Container:    n.resource.Container.ID,
		OutputStream: &buf,
		ErrorStream:  &buf,
		Stdout:       true,
		Stderr:       true,
	})
	if err != nil {
		return fmt.Sprintf("<could not read logs: %v>", err)
	}
	return buf.String()
}

// readFile copies a file out of the container. It goes through base64 rather than raw
// stdout because server.met is binary and the exec stream is chunk-framed; base64 keeps
// the payload text-safe. A missing file yields (nil, false) rather than an error, since
// "not written yet" is a normal state the callers poll on.
func (n *node) readFile(path string) ([]byte, bool) {
	var out, errBuf bytes.Buffer
	code, err := n.resource.Exec(
		[]string{"sh", "-c", fmt.Sprintf("test -f %q && base64 %q", path, path)},
		dockertest.ExecOptions{StdOut: &out, StdErr: &errBuf},
	)
	if err != nil || code != 0 {
		return nil, false
	}
	decoded, decErr := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(out.String()), ""))
	if decErr != nil {
		n.t.Fatalf("%s: decode base64 of %s: %v (stderr=%q)", n.label, path, decErr, errBuf.String())
	}
	return decoded, true
}

// serverMet reads a server.met out of the container and parses it with the production
// codec, so our reader and writer are both validated against whatever wrote the file —
// eserver's 2007 C implementation on one side, ours on the other.
func (n *node) serverMet(path string) []ed2k.ServerMetEntry {
	n.t.Helper()
	raw, ok := n.readFile(path)
	if !ok || len(raw) == 0 {
		return nil
	}
	tmp := filepath.Join(n.t.TempDir(), fmt.Sprintf("%s-%d.met", n.label, time.Now().UnixNano()))
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		n.t.Fatalf("stage %s: %v", tmp, err)
	}
	entries, err := ed2k.ReadServerMet(tmp)
	if err != nil {
		n.t.Fatalf("%s: parse %s (%d bytes): %v", n.label, path, len(raw), err)
	}
	return entries
}

// hostIP is the address on the host that the container's published ports are reachable
// on. Docker reports 0.0.0.0 for a wildcard binding, which is not dialable on every
// platform, so it is normalised to loopback.
func (n *node) hostIP() string {
	ip := n.resource.GetBoundIP("4661/tcp")
	if ip == "" {
		ip = n.resource.GetBoundIP("5555/tcp")
	}
	if ip == "" || ip == "0.0.0.0" || ip == "::" {
		return "127.0.0.1"
	}
	return ip
}

func (n *node) hostPort(id string) string {
	port := n.resource.GetPort(id)
	if port == "" {
		n.t.Fatalf("%s: container port %s is not published", n.label, id)
	}
	return port
}

// waitForStats polls until cond is satisfied, then returns the satisfying snapshot. On
// timeout it fails with the last snapshot and the container log, because "verified never
// reached 1" on its own says nothing about which phase stalled.
func waitForStats(t *testing.T, n *node, timeout time.Duration, what string, cond func(liveStats) bool) liveStats {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last liveStats
	var lastErr error
	for time.Now().Before(deadline) {
		s, err := n.stats()
		if err != nil {
			lastErr = err
		} else {
			last = s
			if cond(s) {
				t.Logf("output: %s reached %s after %s — %s", n.label, what,
					timeout-time.Until(deadline), s)
				return s
			}
		}
		time.Sleep(time.Second)
	}
	t.Fatalf("%s never reached %s within %s (last: %s, lastErr=%v)\nlogs:\n%s",
		n.label, what, timeout, last, lastErr, n.logs())
	return last
}

// waitFor polls an arbitrary condition. Used where the observable is a file or a log line
// rather than a counter.
func waitFor(t *testing.T, timeout time.Duration, what string, cond func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(time.Second)
	}
	t.Logf("condition %q not met within %s", what, timeout)
	return false
}

// containsEntry reports whether a parsed server.met holds ip:port.
func containsEntry(entries []ed2k.ServerMetEntry, ip string, port uint16) bool {
	want := net.ParseIP(ip)
	for _, e := range entries {
		if e.Port == port && e.IP.Equal(want) {
			return true
		}
	}
	return false
}

func describeEntries(entries []ed2k.ServerMetEntry) string {
	if len(entries) == 0 {
		return "<empty>"
	}
	parts := make([]string, 0, len(entries))
	for _, e := range entries {
		parts = append(parts, fmt.Sprintf("%s:%d name=%q desc=%q", e.IP, e.Port, e.Name, e.Description))
	}
	return strings.Join(parts, " | ")
}

// ---------------------------------------------------------------------------
// private helpers
// ---------------------------------------------------------------------------

// buildEnodeImage builds the server image with the module root as the build context. The
// image is built once per test binary and reused, so the go mod download and compile are
// paid once rather than per case.
func buildEnodeImage(t *testing.T, pool *dockertest.Pool) error {
	t.Helper()
	root := moduleRoot(t)
	t.Logf("input: building %s (context=%s, dockerfile=tests/interop/Dockerfile.enode)", enodeImage, root)
	start := time.Now()
	var out bytes.Buffer
	err := pool.Client.BuildImage(dc.BuildImageOptions{
		Name:         enodeImage,
		Dockerfile:   filepath.Join("tests", "interop", "Dockerfile.enode"),
		ContextDir:   root,
		OutputStream: &out,
	})
	if err != nil {
		return fmt.Errorf("%w\nbuild output:\n%s", err, tail(out.String(), 40))
	}
	t.Logf("output: built %s in %s", enodeImage, time.Since(start).Round(time.Second))
	return nil
}

// buildEserverImage stages a build context in a temp directory and builds from it.
//
// The staging exists because a Dockerfile must live inside its own build context: the
// Dockerfile and entrypoint are tracked in tests/interop, while the ELF lives in the
// gitignored lugdunum-eserver tree. Copying both into one temp directory is what lets the
// tracked rig consume the untracked binary.
func buildEserverImage(t *testing.T, pool *dockertest.Pool, binary string) error {
	t.Helper()
	ctxDir := t.TempDir()
	here, err := filepath.Abs(".")
	if err != nil {
		return err
	}
	staged := map[string]string{
		"Dockerfile.eserver":    filepath.Join(here, "Dockerfile.eserver"),
		"entrypoint.eserver.sh": filepath.Join(here, "entrypoint.eserver.sh"),
		"donkey.ini.tmpl":       filepath.Join(here, "donkey.ini.tmpl"),
		"eserver.i686":          binary,
	}
	for dst, src := range staged {
		data, err := os.ReadFile(src)
		if err != nil {
			return fmt.Errorf("stage %s: %w", src, err)
		}
		if err := os.WriteFile(filepath.Join(ctxDir, dst), data, 0o755); err != nil {
			return fmt.Errorf("write %s: %w", dst, err)
		}
	}
	t.Logf("input: building %s (staged context=%s, binary=%s)", eserverImage, ctxDir, binary)
	start := time.Now()
	var out bytes.Buffer
	if err := pool.Client.BuildImage(dc.BuildImageOptions{
		Name:         eserverImage,
		Dockerfile:   "Dockerfile.eserver",
		ContextDir:   ctxDir,
		OutputStream: &out,
	}); err != nil {
		return fmt.Errorf("%w\nbuild output:\n%s", err, tail(out.String(), 40))
	}
	t.Logf("output: built %s in %s", eserverImage, time.Since(start).Round(time.Second))
	return nil
}

// runContainer starts one container on the network and records its addresses.
func runContainer(t *testing.T, pool *dockertest.Pool, network *dockertest.Network,
	label, image string, env, exposed []string) *node {
	t.Helper()

	repo, tag := image, "latest"
	if i := strings.LastIndex(image, ":"); i > 0 {
		repo, tag = image[:i], image[i+1:]
	}
	name := fmt.Sprintf("%s-%s-%d", sanitize(t.Name()), label, nextSequence())

	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Name:         name,
		Hostname:     label,
		Repository:   repo,
		Tag:          tag,
		Env:          env,
		Networks:     []*dockertest.Network{network},
		ExposedPorts: exposed,
	}, func(hc *dc.HostConfig) {
		hc.AutoRemove = true
		hc.RestartPolicy = dc.RestartPolicy{Name: "no"}
		hc.PublishAllPorts = true
	})
	if err != nil {
		t.Fatalf("start %s (%s): %v", label, image, err)
	}
	t.Cleanup(func() { _ = pool.Purge(resource) })

	n := &node{t: t, pool: pool, resource: resource, label: label}
	n.ip = resource.GetIPInNetwork(network)
	if n.ip == "" {
		t.Fatalf("%s has no address on the interop network", label)
	}
	n.ip6 = ipv6InNetwork(resource, network)
	t.Logf("input: started %s as %s ip=%s ip6=%s env=%v", label, name, n.ip, orNone(n.ip6), env)
	return n
}

// ipv6InNetwork reads the container's global IPv6 on the given network, empty on a
// v4-only network. dockertest's GetIPInNetwork only exposes the v4 address.
func ipv6InNetwork(r *dockertest.Resource, network *dockertest.Network) string {
	if r.Container == nil || r.Container.NetworkSettings == nil {
		return ""
	}
	cfg, ok := r.Container.NetworkSettings.Networks[network.Network.Name]
	if !ok {
		return ""
	}
	return cfg.GlobalIPv6Address
}

// nextSequence keeps container names unique within a run; a name collision on
// CreateContainer is a hard failure, and several cases start the same label.
func nextSequence() int {
	containerSeqMu.Lock()
	defer containerSeqMu.Unlock()
	containerSequence++
	return containerSequence
}

// sanitize reduces a Go test name to something Docker accepts as a name component.
func sanitize(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	return strings.Trim(b.String(), "-")
}

func tail(s string, lines int) string {
	parts := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(parts) <= lines {
		return s
	}
	return strings.Join(parts[len(parts)-lines:], "\n")
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}
