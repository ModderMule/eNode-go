# eNode-go

Go port of the original `eNode` eD2K/eMule server codebase.

[中文说明](README.zh-CN.md)

Protocol doc: [Server <=> Client Communication (OP_ meanings)](docs/server-client-communication.md)

## Included

- Core eD2K protocol modules (`ed2k/*`)
- Runtime entrypoint (`cmd/enode/main.go`)
- YAML config loader (`config/*`)
- Storage engines:
  - `memory`
  - `mysql` (real `database/sql` + `go-sql-driver/mysql`)
  - `mongodb` (real official MongoDB Go driver)
- Unit tests for core modules
- Dockertest integration tests for real MySQL/Mongo backends

## Features

- TCP/UDP opcodes
- TCP/UDP protocol obfuscation
- Obfuscated lowID detection
- Lugdunum/eMule extended protocol
- gzip compression
- LowID callbacks (IPv4, and IPv6 via `OP_CALLBACKREQUESTED_IPV6` when the requester
  is only reachable over IPv6)
- NAT traversal server (`OP_VC_NAT_HEADER`, `OP_NAT_REGISTER`, `OP_NAT_SYNC2`):
  dual-stack UDP hole-punching for LowID↔LowID and firewalled IPv6↔IPv6 peers (a v4
  and a v6 candidate per client, v6 preferred); gated by `natTraversal.ipv6` (default
  on). The registry is login-independent, so `natTraversal.serverIndependent` (default
  on) pairs clients across **different servers or no server** — cross-server /
  serverless LowID↔LowID — advertised via `SRV_TCPFLG_NAT_RENDEZVOUS (0x40000)` + an
  `OP_SERVERIDENT` NAT-port tag. See
  [`docs/ipv6-client-implementation-spec.md`](docs/ipv6-client-implementation-spec.md) §9.
- Files larger than 4 GiB
- Server-to-server gossip: the Lugdunum `OP_SERVER_LIST_REQ/RES` handshake, so
  `OP_SERVERLIST` is populated from the live network instead of only a static list.
  Verified against the original **eserver 17.14** binary running beside us on a Docker
  network — see [`docs/server-gossip.md`](docs/server-gossip.md) for the protocol and
  [`docs/interop-docker-tests.md`](docs/interop-docker-tests.md) for the test rig.
- Access filters: `ipfilter.dat` ranges and MaxMind GeoIP country blocking, both dropping
  a refused address before any wire parsing. See
  [`docs/access-filters.md`](docs/access-filters.md).
- Admin dashboard: a self-contained tabbed HTML page served over HTTP with only the
  Go standard library (zero third-party deps). The Status tab shows live client / file /
  LowID / peer-server counts, listening ports, enabled features, version and uptime;
  further tabs list clients, files, peer servers, filters, bans, automated queriers,
  refusals, health, runtime, accounts and the effective configuration (secrets hidden).
  Default on and bound to `127.0.0.1` only; everything beyond the Status tab needs
  loopback or `admin.username` / `admin.password`. See [`docs/admin-status-dashboard.md`](docs/admin-status-dashboard.md).
  A public `GET /healthz` and `GET /status` are served by the Meta API HTTP listener;
  see [`docs/meta-api.md`](docs/meta-api.md#health-and-status).
- IPv6 dual-stack: accepts IPv6 client logins, records and verifies each client's
  IPv6, publishes IPv6 sources, and advertises IPv6 peer servers in `OP_SERVERLIST`
  (eMuleAI/eMuleQt `CT_MOD_*` compatible). See
  [`docs/ipv6-client-implementation-spec.md`](docs/ipv6-client-implementation-spec.md).
  Disable with `ipv6.enabled: false` for the exact IPv4-only behaviour.
- Memory-engine snapshots: the in-RAM index can be persisted to a gob file
  periodically and on shutdown, and reloaded at startup, so a restart does not have
  to re-learn the index from client re-offers. Off by default; restoring reproduces
  what a mysql-backed server looks like after a restart. See
  [`docs/storage-snapshot.md`](docs/storage-snapshot.md).
- Per-client file publish limits: Lugdunum's `softLimit` / `hardLimit`, now configurable
  and actually enforced. The soft limit is how many distinct files a client may publish
  at a time: past it a client is warned once and its new files are ignored. The hard
  limit is how many files one packet may declare: at it the client is told why and
  disconnected, which a stock eMule, sending 200 files per packet, never is. See
  [`docs/server-client-communication.md`](docs/server-client-communication.md#per-client-publish-limits).
- Torrent, Usenet, Kad and web results in eD2K search: keywords of every TCP and UDP
  search are forwarded to the torrent-crawler / usenet-crawler / kademlia-crawler /
  web-crawler daemons over their `MetaIngest` service (gRPC-compatible, via the shared
  [`enodemeta`](https://github.com/ModderMule/enodemeta) contract), and their releases
  come back merged into the same reply. Torrent, Usenet and web rows use a pseudo-hash
  and `FT_META_*` tags, Kad rows are real eD2K files, and each carries a filename
  prefix (`[torrent] ` / `[usenet] ` / `[kad] ` / `[web] `) so stock clients can tell
  them apart. Each network, its feed subscription and a result cache are optional and
  off by default. See [`docs/meta-search.md`](docs/meta-search.md).
- Login required before any request: every TCP opcode but `OP_LOGINREQUEST` and
  `OP_DISCONNECT` is refused on a session that has not logged in, so nothing can reach
  the index without an identity the server can account for and clean up. See
  [`docs/server-client-communication.md`](docs/server-client-communication.md#login-precondition).
- Files identified by `(hash, size)`, as the protocol intends: all three storage engines
  key on the pair, so an offer carrying a known hash at a different size gets its own
  record instead of overwriting someone else's. A record with no usable size is refused
  outright — it could never be served. See
  [`docs/server-client-communication.md`](docs/server-client-communication.md#file-identity).
- ed3k index node (optional, off by default): the server also serves ed3k, the
  QUIC successor network of eD2K, as an index node without Kad routing duty. It
  stores sources, keywords and notes for every file in the configured storage engine
  (memory, MySQL, MongoDB, with Manticore for keyword search), relays hole-punch
  requests, and is advertised to eD2K clients in `OP_SERVERIDENT` (`ST_ED3K`). An
  optional bridge lists ed3k nodes that also speak eD2K as eD2K sources. See
  [`docs/ed3k-index-node.md`](docs/ed3k-index-node.md).
- Easy support for multiple storage engines

## NAT Traversal Transfer Screenshot

![NAT traversal transfer screenshot](docs/images/E35D333390376E311EA081CAD69D85D7.png)

## Configuration

Runtime config is YAML:

- `enode.config.yaml`

Start command supports custom path:

```bash
go run ./cmd/enode -config enode.config.yaml
```

Full config field reference:

```yaml
name: "eNode-go"             # Server name shown to clients
description: "emule-qt.org"  # Server description shown to clients
address: ""                  # Local bind address; default is 0.0.0.0
dynIp: "auto"                # Public advertised IP; auto resolves via testUrls
testUrls:                    # Used only when dynIp=auto, first valid IPv4 wins
  - "https://4.ipw.cn"
  - "https://ip.3322.net"
  - "https://api.ipify.org"
  - "https://checkip.amazonaws.com"

messageLowID: "You have LowID."   # Message sent to LowID clients
messageLogin: |-                  # Message sent on login; may span several lines
  Welcome to eNode-go!
  An experimental ed2k server written in Go.
  Get eMule-Qt, the modern open-source ed2k client: https://emule-qt.org/

servers: []                  # Peer servers advertised in OP_SERVERLIST; empty is the default.
  # - ip: "192.0.2.10"        # ip may be IPv4 or a public IPv6 (v6 goes in the trailing v6 block)
  #   port: 4661
  # - ip: "2001:db8::10"
  #   port: 4661

noAssert: false              # Compatibility assert switch (normally false)
logLevel: "debug"            # Log level: debug|info|warn|error
logFile: "logs/enode.log"    # Log file path
logRotate:                   # Size limit of logFile; SIGHUP reopens the log files
  maxSizeMB: 500             # Limit in MB; -1 = no limit (external logrotate)
  enabled: true              # true: rotate to enode-<time>.log; false: empty the file in place
  maxBackups: 1              # Rotated files kept
  compress: false            # gzip rotated files

supportCrypt: true           # Enable protocol obfuscation support
requestCrypt: true           # Request obfuscation from clients
requireCrypt: true           # Require obfuscation from clients
auxiliarPort: false          # Advertise auxiliary port capability
IPinLogin: false             # Include IP in login flow

tcp:
  port: 5555                 # Main TCP port
  portObfuscated: 5565       # Obfuscated TCP port (when supportCrypt=true)
  maxConnections: 1000000    # Max concurrent connections
  connectionTimeout: 2000    # Connect-stage timeout (ms)
  disconnectTimeout: 3600    # Idle disconnect timeout (s)
  loginTimeout: 60           # Seconds from accept to a completed login, not extended by traffic
  maxConnectionsPerIP: 32    # Concurrent connections per address (IPv6 /64), both TCP ports; 0 = off
  allowLowIDs: true          # Allow LowID clients
  minLowID: 1                # Minimum allocated LowID
  maxLowID: 16777215         # Maximum allocated LowID

udp:
  port: 5559                 # Main UDP port (tcp.port + 4, where eMule pings the plaintext stat)
  portObfuscated: 5567       # Obfuscated UDP port; must be tcp.port + 12 for the crypt-ping (see docs/server-udp-crypt-ping.md)
  portGossip: 5569           # Obfuscated server-to-server source port / advertised portUDPOBF; tcp.port + 14 on its own socket, open it when gossip is enabled (see docs/server-gossip.md)
  getSources: true           # Enable UDP source queries
  getFiles: true             # Enable UDP file queries
  serverKey: 0               # 0: per-client UDP obfuscation keys derive from a generated 128-bit secret in data/udp.secret; non-zero: a legacy 32-bit secret (see docs/server-udp-crypt-ping.md)
  rateLimitPerIPPerMinute: 120 # UDP searches + source requests per address (IPv6 /64) per minute; 0 = off

files:                       # Per-client publish caps (see docs/server-client-communication.md)
  softLimit: 10000           # Distinct files per client; new files past it are ignored and the client is warned once; 0 = unlimited
  hardLimit: 20000           # Files per OP_OFFERFILES packet; at it the client is told why and disconnected; 0 = unlimited

ed3k:                        # ed3k index node (see docs/ed3k-index-node.md); off by default
  enabled: false
  port: 0                    # UDP port; 0 = the number of tcp.port (ed3k's port rule)
  listen: ""                 # Bind address; "" = every address of both families
  advertise: ""              # IPv4 in the advertised link; "" = the server's advertised IP
  advertiseIPv6: ""          # IPv6 in the link; "" = ipv6.dynIp6 when it names one
  keyFile: "data/ed3k.key"   # Ed25519 node key, created on first start; the node ID derives from it
  network: ""                # Name of a test or closed network; "" = the public ed3k network
  nick: ""                   # Sent in the node's Hello
  requestsPerMinute: 120     # KadRequests per address, kind and search/store; beyond: BUSY
  limits:
    maxConnections: 50000    # Open connections in all
    connectionsPerHost: 256  # Per IPv4 /32 or IPv6 /64
    connectionsPerSite: 1024 # Per /24 or /48
    newPerHostPerMinute: 120 # New connections per address and minute
    relayLeaves: 1024        # Hole-punch relay reservations in all
    relayPerHost: 8
    relayPerSite: 32
    recordsPerHost: 50000    # Records one address may have stored, over all files
    recordsPerSite: 200000
    maxRecords: 50000000     # Records in the store; beyond: BUSY
  bridge:
    enabled: true            # List TCP-tested ed3k nodes as eD2K sources (outgoing TCP connects); needs ed3k.enabled
    maxPerAnswer: 20         # ed3k sources added to one OP_FOUNDSOURCES
    tcpTestMinutes: 30       # How long a TCP test result is kept

natTraversal:
  enabled: true              # Enable NAT traversal service
  port: 2004                 # NAT traversal UDP port
  ipv6: true                 # IPv6 hole-punching (dual-stack candidates); needs ipv6.enabled
  serverIndependent: true    # Cross-server / serverless LowID↔LowID rendezvous (default on)
  registrationTTLSeconds: 30 # NAT registry TTL (seconds)

ipv6:                        # IPv6 dual-stack; omit the whole block for IPv4-only behaviour
  enabled: true              # Accept IPv6 logins and run the v6 code paths (default true)
  address: ""                # Explicit IPv6 bind; "" lets the top-level address govern
  dynIp6: "auto"             # Public IPv6, "auto" to resolve via testUrls6, or "" to not advertise
  publishSources: true       # Emit the IPv6 sentinel and honour the OP_*_IPV6 opcodes
  probeReachability: true    # Verify a client's IPv6 is reachable before publishing it
  testUrls6:                 # Used only when dynIp6=auto, first valid IPv6 wins (temporary ones swapped for a stable one)
    - "https://v6.ident.me"
    - "https://api64.ipify.org"

admin:                       # Local admin dashboard (stdlib-only HTTP page)
  enabled: true              # Default on; an absent block still enables it
  bindIP: "127.0.0.1"        # Loopback only; "0.0.0.0" / "::" exposes it on all interfaces
  port: 4560                 # HTTP port
  username: ""               # Basic-auth login for non-loopback clients; set both or
  password: ""               # neither. Without them, off-box clients see the status tab only

storage:
  engine: memory             # Storage engine: memory | mysql | mongodb
  cleanup:                   # Expire offline clients and their sources
    enabled: true            # Turn the periodic cleanup on
    staleAfterHours: 24      # Age after which an offline client is removed
    intervalMinutes: 60      # How often the cleanup sweep runs
    keepZeroSourceFiles: true # Keep files whose last source went offline (default true)
    batchSize: 1000          # Rows deleted per sweep batch
  snapshot:                  # Persist the memory-engine index across restarts
    enabled: false           # Off by default; memory engine only
    file: "data/storage.gob" # Written by the server, hence under data/
    intervalMinutes: 15      # How often the snapshot is rewritten
    compress: true           # gzip the gob; the reader detects either form
  mysql:
    host: localhost          # MySQL host
    port: 3306               # MySQL port
    user: enode              # MySQL user
    pass: password           # MySQL password
    database: enode          # MySQL database
    connections: 8           # MySQL connection pool cap
    deadlockDelay: 100       # Base deadlock retry delay (ms), doubled per retry with jitter, 6 retries
    schemaFile: misc/enode.sql # DDL applied on first connect when tables are missing
    dialect: mariadb         # Full-text search: mariadb (portable) | mysql (ngram substring)
  mongodb:
    host: 127.0.0.1          # MongoDB host (used when uri is empty)
    port: 27017              # MongoDB port (used when uri is empty)
    database: enode          # MongoDB database name
    uri: ""                  # MongoDB URI; takes precedence when set
```

`address` vs `dynIp`:
- `address` controls local bind/listen address on this machine.
- `dynIp` controls the public IP advertised to clients.

For MySQL:

```yaml
storage:
  engine: mysql
  mysql:
    host: localhost
    port: 3306
    user: enode
    pass: password
    database: enode
    connections: 8
```

For MongoDB:

```yaml
storage:
  engine: mongodb
  mongodb:
    uri: mongodb://localhost:27017
    database: enode
```

## Install & Update

Download [`update.sh`](https://github.com/ModderMule/eNode-go/releases/latest/download/update.sh)
into an empty directory and run `bash update.sh`. Arguments are passed on to enode, e.g. `bash update.sh -daemon` to start
in the background or `bash update.sh -config config.yaml` for another config file.
It installs the latest release for your platform and updates that install on later runs.

When enode is already running from that directory, an update does not disconnect anyone:
the running server hands every connection and its index to the new binary, which carries
on serving them (Linux and macOS). `kill -USR2 <pid>` does the same by hand. See
[docs/server-handoff.md](docs/server-handoff.md).

## Build & Test

The meta search contract module (`enodemeta`) is a git submodule, so clone with
`git clone --recurse-submodules`, or run `git submodule update --init` in an existing
checkout. Go 1.25 or newer.

Run all standard tests:

```bash
go test ./...
```

Run real DB integration tests (Docker required):

```bash
ENODE_INTEGRATION=1 go test ./storage -run Dockertest -v
```

This spins temporary MySQL and MongoDB containers, initializes schema/data, and verifies backend behavior end-to-end.

## Thanks To

- David Xanatos

## Notes

- The original Node.js repository remains separate; this directory is the Go implementation.
- If Docker is unavailable, integration tests are skipped unless explicitly enabled.
