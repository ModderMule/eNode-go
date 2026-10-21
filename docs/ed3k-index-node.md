# ed3k index node

eNode-go can run an **ed3k index node** beside its eD2K server. ed3k is the QUIC/protobuf
successor network of eD2K, specified in the eMuleQt repository (`docs/ed3k-spec`,
`Protocol.md` draft 0.2 plus the index-node rulings of 2026-10-21). An index node is
"what eD2K calls a server" (§11). Clients:
- store their sources and keyword records at the index node;
- search there;
- use it as a hole-punch relay.

The feature is **off by default** (`ed3k.enabled: false`). With it off:
- no socket is bound;
- no table or collection is created;
- every eD2K packet is byte for byte what it was before.

## What it is, and what it is not

| | |
|---|---|
| Role | `INDEX` without `ROUTER` (§2, §11 "Kad duty"). The node is in no routing table, keeps none, answers without contacts and **never dials**. |
| Stores | `SOURCE`, `KEYWORD`, `NOTE`, for every target. Every other kind (sets, aliases, live, friends, …) is answered as "not responsible", so clients use Kad for those (§10.3). |
| Relay | Yes: `Relay` reservations and `Punch` forwarding (§9.4, §9.5), the ed3k form of an eD2K callback. |
| ReachTest | Answered `ok = false`: without a routing table there is no prober to pick (§11). |
| File transfer | No. The server shares nothing; `FileRequest` and the other transfer types are `UNSUPPORTED`. |
| Hello caps | `INDEX \| RELAY \| ED2K`, `RELAY` cleared while every relay slot is taken; `nat = 1` (open, by the operator's word). |
| Keepalive | `max_idle_timeout` 300 s and no PING of its own (§11 Keepalive). |

## Configuration

The `ed3k:` section is in every config file. The commented reference is
`enode.config.yaml`. The keys that matter:

- `enabled`: off by default.
- `port`: `0` takes the number of `tcp.port`. That is the spec's port rule (§14.1), and it
  cannot collide with the server's eD2K UDP port, which is `tcp.port + 4`. Open this UDP
  port in the firewall.
- `advertise` / `advertiseIPv6`: the addresses in the link that `OP_SERVERIDENT`
  advertises. Empty takes the server's advertised IPv4 and its `ipv6.dynIp6`. A private
  address in the link is refused by clients on the public network, and the server logs a
  warning.
- `keyFile` (default `data/ed3k.key`): the Ed25519 seed. The **node ID** derives from it.
  Losing the file changes the node ID and the link, and clients have to learn the new one
  from `OP_SERVERIDENT`.
- `network`: the name of a test or closed network. Empty is the public ed3k network. A
  closed network's name is its secret, so it is redacted like a password.
- `limits.*`: connection, relay and record bounds. The spec lets an index node widen the
  per-address limits of an ordinary node, because many of its clients share one
  carrier-grade NAT address (§4.6, §9.4). `recordsPerHost` and `recordsPerSite` are the
  bound over all targets that §11 makes a MUST for an index node.
- `bridge.*`: see "eD2K bridge" below.

Changing anything in the section needs a restart.

### Storage

The records live in the configured `storage.engine`:

| Engine | Tables / collections | Notes |
|---|---|---|
| memory | in process | Lost on restart. Clients republish (sources every 5 h or less, keywords within 24 h). |
| mysql / mariadb | `ed3k_targets`, `ed3k_sources`, `ed3k_keywords`, `ed3k_notes`, `ed3k_state` | Created by an idempotent DDL (`storage/ed3k_mysql.sql`) at the first start with ed3k on. |
| mongodb | the same names, as collections | Indexes are created at the first start with ed3k on. |
| + Manticore | `<storage.manticore.table>_ed3k` | A mirror of the keyword records for word search, see below. |

The database is authoritative. Several eNode-go instances that share one database share
one ed3k index:
- They agree on limits and FULL, because every store locks its target row (MySQL
  `SELECT … FOR UPDATE`, a lease document on Mongo).
- They agree on the paging secret, which is kept in `ed3k_state` and replaced every 24 h
  by whichever instance gets there first.

Limits per target (spec defaults):

| Kind | Per target | Per publisher host / site | Lifetime |
|---|---|---|---|
| SOURCE | 10,000, then `FULL` | 8 / 32 | 5 h, longer while the publishing connection stays open (§11) |
| KEYWORD | 100,000 files, 3 records per file | 1,000 files per key, 2,000 per site | 24 h |
| NOTE | 64, then `FULL` | 4 / 8 | 24 h |

There is also a node-wide bound per host and site (`limits.recordsPerHost`,
`limits.recordsPerSite`): a record beyond it is `REJECTED`. `limits.maxRecords` makes
every store `BUSY` once the store is full.

**Manticore.** When `storage.manticore.enabled` is on, keyword searches that name words
(`Query.all`) run on Manticore:
- Each word is indexed as a hash token, so matches are exact and whole-word, as ed3k
  wants (§10.3), whatever Manticore's charset.
- The table is rebuilt at startup and after every rotation of the paging secret.
- After each stored keyword record, the kept records of that file are copied over its
  documents.
- Every other search, and every search while the mirror is not ready, runs on the
  database. `-reindex-manticore` also drops and rebuilds the ed3k table.

## eD2K integration

| Tag | Where | Value |
|---|---|---|
| `ST_ED3K` 0xE3 (string) | `OP_SERVERIDENT` and the extended `OP_SERVER_DESC_RES` | `ed3k:node?id=<32 hex>&ep=<ip:port>[&ep=[ip6]:port]` |
| `CT_ED3K` 0xE3 (hash) | `OP_LOGINREQUEST` | the client's 16-byte ed3k node ID |

- Both are from the spec's `docs/ed2k-tags.md` §2. 0xE3 is free in the server-tag and
  login-tag spaces of every surveyed client and server. Both eMule and eMuleQt skip a tag
  they do not know.
- The tags are mirrored in the enodemeta `tags` contract (`STEd3k`, `CTEd3k`).
- **Gossip:** a peer server's `ST_ED3K` is read from its description reply and kept in
  the peer table (`PeerServer.Ed3k`). It is informational only, because ed3k has no
  server list.
- **Admin:** the dashboard has an "ed3k index node" section. The client view shows each
  session's `CT_ED3K` node ID.

### eD2K bridge (`ed3k.bridge.enabled`, on by default)

The bridge runs only while `ed3k.enabled` is on; with ed3k off the setting does nothing.
Set `bridge.enabled: false` to keep the node from making outgoing TCP connects.

The spec's `docs/ed2k-tags.md` §6 allows a server to list some ed3k nodes as eD2K
sources in `OP_FOUNDSOURCES` (and the OBFU form, and UDP global source answers). A node
is listed for an MD4 hash when all of these hold:
1. It holds a live SOURCE record here, stored with the `ED2K` capability in its Hello.
2. It said `nat = open`, on a direct IPv4 connection.
3. A KEYWORD record signed by the same key gives `FileInfo.ed2k` = that MD4 hash for the
   file.
4. The server's own TCP connect to the node's observed address, at the same port number,
   succeeded.

About the TCP test (condition 4):
- ed3k's "open" is a UDP result, so the server tests TCP itself.
- Tests run in the background, at most 16 at a time, and results are kept
  `bridge.tcpTestMinutes`.
- A node is never listed before its test has passed.

The user hash and the crypt options of a listed source come from the eD2K session whose
`CT_ED3K` login names the node ID. They are used **only if that session comes from the
node's own address**, because a login tag is a claim. Otherwise the source goes out
without a user hash.

The other direction, eD2K sources as ed3k records, is impossible: eD2K has no BLAKE3
root.

## Protocol coverage

| Spec | Status |
|---|---|
| §4.1 QUIC profile | QUIC v1, ALPN `ed3k/1`, no SNI, RFC 7250 Ed25519 raw keys on both sides (a vendored TLS and quic-go, see `docs/ed3k-tls-quic-forks.md`). No 0-RTT and no session tickets. 64 streams per direction, no uni streams. A client without a key fails in TLS with `certificate_required` (allowed instead of `NO_KEY`). |
| §4.3–§4.5 obfuscation | Every datagram masked: `salt ‖ mask(magic ‖ kp ‖ pad ‖ body)`, BLAKE3 keyed XOF, partial mask of DATA, the salt re-roll rule. Long-header datagrams are split into 2–4 fragments for the first 2 flights per type. Reassembly bounds as specified. Anti-amplification counts this layer's bytes. PROBEs are dropped (never answered). Path MTU discovery is off and the QUIC size stays 1,200, which an index node may do: it sends no file data (§4.4). |
| §4.6 budget | Per node ID (10/min, then a 24 h ban), per host (configurable), open per host / site / total, private addresses exempt in a named network. |
| §5 framing | Frames with the 1 MiB limit and 10-byte varints. Magicless zstd decoded under the profile (exactly one frame, window and output ≤ 1 MiB, no dictionary held) and written under it when it pays. Hello on stream 0 within 30 s, no answers before it. |
| §6 identity | Node ID, `obf_id`, routing ID (CRC32C), §14.2 derived user hash, `ed3k:node` links. |
| §10.3 KadRequest | Check order, `want = 0`, paging by `H("ed3k v1 page", secret ‖ …)` with a 24 h secret, ≤ 100 per answer, ≤ 256 records per Store, `also` (≤ 256), the rate limit (store `BUSY` / search `Error{BUSY}`), `load` and `spill`. |
| §10.7 signed records | Strict Ed25519 (canonical A and R, neither of small order, S < L, cofactorless), one signature per algorithm, unknown algorithms kept, ≤ 1 KiB measured canonically, expiry window, tokenizer check of the keyword, the "byte-identical ⇒ OLDER without verifying" shortcut (§11 Load). |
| §10.8 keyword load | The 3-place rule by site and freshness, `signer` restrictions, per-key and per-site file limits, level size. |
| §11 | Responsible for every target from the start, sources kept while the connection is open (renewed hourly, released at close), the node-wide bound per host and site. |
| §9.4 / §9.5 | Reservations (one per leaf node ID, per host / site / total), Punch forwarding over the leaf's own connection with observed endpoints and `seen`, a 5 s wait, forward limits (30/min per leaf, 3/min per initiator host and leaf), `NOT_FOUND`, `DENIED` for a forwarded Punch, `MALFORMED` for `seen > 2`. |
| §10.1 tokenizer | NFKC, full case folding, NFKC, Cf removed, the unspaced-script pair rule and the extension rule. Needs Unicode ≥ 16 tables: go.mod is `go 1.27` and x/text ≥ v0.34, and the node refuses to start on older tables. |

Not done:
- the record kinds of extensions;
- `ROUTER` duty;
- 0-RTT;
- a node-list source (bootstrap.md §5 needs nodes the signer dialled itself);
- the HTTP/link attachments of SOURCE records, which are accepted and ignored;
- ALIAS records of scheme `ed2k` as a bridge proof.

## Tests

- **Spec vectors** (`go test ./ed3k/...`): identity, routing ID, targets, every tokenizer
  edge case, the signed record and its five rejected signatures (Go's stdlib accepts
  three of them), and the obfuscation keys and whole datagrams.
- **TLS:** `internal/ed3k/itls/tls/rawkey_test.go` covers mutual raw keys, a client
  without raw keys, a client without a key, and the wrong peer.
- **Transport:** QUIC over the obfuscating socket, on the public and a named network.
- **Node:** Hello, errors, a keyword and source round trip, relay and Punch, all with
  in-process clients.
- **Store conformance suite** (`storage/ed3k_test.go`): runs on memory by default.
  `ENODE_INTEGRATION=1` runs it on MySQL 8, MariaDB 11, MongoDB 7 and MySQL + Manticore
  (Docker). The Manticore test also checks that 200 random word searches page exactly as
  the database does.
- **Interop with packmule** (the Rust reference, `eMuleQt/libs/packmule`): set
  `ENODE_ED3K_PACKMULE=<path to packmule-node>`.
  - `ed3k/transport` dials packmule (Go RPK client against rustls) and exchanges Hello.
  - `ed3k` has packmule dial this node (rustls client against the Go server) and
    exchange Hello and a KadRequest.
  - packmule publishes only through Kad ROUTERs and has no index-client option, so its
    `--share` does not reach a node without ROUTER. That test only reports what was
    published.

## Operations

- **Handover (SIGUSR2):** the UDP socket is passed to the successor like the eD2K sockets.
  QUIC connections themselves do not survive a handover; clients reconnect, and kept
  sources stay until their normal lifetime.
- **Resources:** an idle QUIC client costs about 65 KiB against about 21 KiB for an eD2K
  TCP session (`docs/quic-vs-tcp-memory-benchmark.local.md`). The 300 s idle timeout and
  the client-side PING intervals of §11 keep the keepalive traffic far below the 20 s
  default.
- **CPU:** every new or changed KEYWORD and NOTE record costs one Ed25519 verification.
  Renewals that are byte for byte the record held cost none.
