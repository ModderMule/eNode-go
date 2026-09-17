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
  serverless LowID↔LowID — advertised via `SRV_TCPFLG_NAT_RENDEZVOUS (0x8000)` + an
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
- Admin status dashboard: a single self-contained HTML page served over HTTP with
  only the Go standard library (zero third-party deps), showing live client / file /
  LowID / peer-server counts, listening ports, enabled features, version and uptime.
  Default on and bound to `127.0.0.1` only; live figures poll a `/stats.json`
  endpoint. See [`docs/admin-status-dashboard.md`](docs/admin-status-dashboard.md).
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
  and actually enforced. Past the soft limit a client is warned once and its excess files
  are ignored; past the hard limit it is told why and disconnected. Counted cumulatively
  across a session, because eMule never sends more than 200 files in one packet. See
  [`docs/server-client-communication.md`](docs/server-client-communication.md#per-client-publish-limits).
- Login required before any request: every TCP opcode but `OP_LOGINREQUEST` and
  `OP_DISCONNECT` is refused on a session that has not logged in, so nothing can reach
  the index without an identity the server can account for and clean up. See
  [`docs/server-client-communication.md`](docs/server-client-communication.md#login-precondition).
- Files identified by `(hash, size)`, as the protocol intends: all three storage engines
  key on the pair, so an offer carrying a known hash at a different size gets its own
  record instead of overwriting someone else's. A record with no usable size is refused
  outright — it could never be served. See
  [`docs/server-client-communication.md`](docs/server-client-communication.md#file-identity).
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
name: "(TESTING!!!) eNode"   # Server name shown to clients
description: "eNode ..."     # Server description shown to clients
address: ""                  # Local bind address; default is 0.0.0.0
dynIp: "auto"                # Public advertised IP; auto resolves via testUrls
testUrls:                    # Used only when dynIp=auto, first valid IPv4 wins
  - "https://4.ipw.cn"
  - "https://ip.3322.net"
  - "https://api.ipify.org"
  - "https://checkip.amazonaws.com"

messageLowID: "You have LowID."   # Message sent to LowID clients
messageLogin: "Welcome to eNode!" # Message sent on login

servers: []                  # Peer servers advertised in OP_SERVERLIST; empty is the default.
  # - ip: "192.0.2.10"        # ip may be IPv4 or a public IPv6 (v6 goes in the trailing v6 block)
  #   port: 4661
  # - ip: "2001:db8::10"
  #   port: 4661

noAssert: false              # Compatibility assert switch (normally false)
logLevel: "debug"            # Log level: debug|info|warn|error
logFile: "logs/enode.log"    # Log file path

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
  allowLowIDs: true          # Allow LowID clients
  minLowID: 1                # Minimum allocated LowID
  maxLowID: 16777215         # Maximum allocated LowID

udp:
  port: 5559                 # Main UDP port (tcp.port + 4, where eMule pings the plaintext stat)
  portObfuscated: 5567       # Obfuscated UDP port; must be tcp.port + 12 for the crypt-ping (see docs/server-udp-crypt-ping.md)
  portGossip: 5567           # Obfuscated server-to-server source port / advertised portUDPOBF; shares the socket above (see docs/server-gossip.md)
  getSources: true           # Enable UDP source queries
  getFiles: true             # Enable UDP file queries
  serverKey: 305419896       # Server-wide secret; per-client UDP obfuscation keys are derived from it + the client IP (see docs/server-udp-crypt-ping.md)

files:                       # Per-client publish caps (see docs/server-client-communication.md)
  softLimit: 10000           # Past this the excess is ignored and the client is warned once; 0 = unlimited
  hardLimit: 20000           # Past this the client is told why and disconnected; 0 = unlimited

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
  testUrls6:                 # Used only when dynIp6=auto, first valid IPv6 wins
    - "https://v6.ident.me"
    - "https://api64.ipify.org"

admin:                       # Local admin status dashboard (stdlib-only HTTP page)
  enabled: true              # Default on; an absent block still enables it
  bindIP: "127.0.0.1"        # Loopback only; "0.0.0.0" / "::" exposes it on all interfaces
  port: 4560                 # HTTP port (no authentication — keep it loopback-only)

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

## Build & Test

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
