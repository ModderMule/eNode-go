# Server-to-server search

Two eD2K servers that both run this can search each other's file catalogue and
walk the whole of it, page by page. A server then answers its own clients with
files that users of the *other* server share.

It is off by default (`serverSearch.enabled`), and each half of it has its own
switch. The wire contract is `ServerSearch` in the `enodemeta` submodule
(`proto/enode/meta/v1/server.proto`); its normative text is
`enodemeta/docs/server-search-contract.md`. This document describes eNode-go's
side of it.

**No client is ever identified to another server.** An answer carries files and
source counts. It never carries an address, a port, a client id, a user hash or
a source. See [Privacy](#privacy).

## Wiring

```
                 server A                                   server B
  ┌────────────────────────────────┐         ┌────────────────────────────────┐
  │ eD2K clients ──► storage.Engine│         │ storage.Engine ◄── eD2K clients│
  │                     │          │         │        │                       │
  │        serverlink.Service ◄────┼─────────┼── serverlink.Searcher          │
  │        (listener :4673)        │ Search  │     │ live search (cache)      │
  │                                │ Browse  │     │ mirror (storage.Mirror)  │
  │                                │         │     ▼                          │
  │                                │         │  ed2k search answer            │
  └────────────────────────────────┘         └────────────────────────────────┘
        the same in the other direction when both have it on
```

| Piece | Where | What it does |
|---|---|---|
| Contract | `enodemeta/proto/enode/meta/v1/server.proto` | The three calls and their messages |
| Catalogue walk | `storage.Engine.BrowseFiles` | Keyset paging over a server's own files, on all three engines |
| Service | `serverlink/service.go`, `auth.go`, `server.go` | Answers other servers |
| Client | `serverlink/client.go` | Calls another server, with token and certificate pin |
| Searcher | `serverlink/searcher.go` | Live search, peer set, catalogue walks |
| Mirror | `storage/mirror.go` | The in-memory copy of other servers' catalogues |
| Advertisement | `ed2k/gossip.go`, `ed2k/udpoperations.go` | Flag bit and tags, gossip mode only |
| Process wiring | `cmd/enode/serversearch.go` | Builds, starts and combines the above |

## The calls

| RPC | Purpose |
|---|---|
| `GetServerInfo` | Name, file count, what is served, the limits, the catalogue epoch |
| `SearchFiles` | Keyword search, paged by offset |
| `BrowseFiles` | Walk of the whole catalogue, paged by token |

All three need the caller to be admitted (see [Who may call](#who-may-call)).
The listener speaks gRPC, gRPC-Web and the Connect protocol on one port, over
TLS when a certificate is configured and h2c otherwise.

### What is served

**Only this server's own eD2K files, and only those a connected client offers
now.** Torrent, Usenet and Kad rows from the catalogue daemons are not served,
and neither is anything in the mirror. A file that came from another server
therefore never travels on to a third.

### SearchFiles

**Request.** `query` is keywords, all of which must match the file name.
`exclude`, `type`, `min_size`, `max_size` and `min_sources` narrow it. The
service turns them into the same `storage.SearchExpr` tree an eD2K search uses
and runs `Engine.FindBySearch`.

**Paging.** The result is sorted (most sources first, then by hash) and kept in
a cache for `serve.cache.ttlSeconds`, so that paging through it is stable. The
caller follows `next_offset`; zero means the last page. `limit` is capped at
`serve.maxSearchLimit`.

**Reach.** A search reaches at most 1000 files, the engines' own ceiling. To
read everything a caller browses.

### BrowseFiles

**Paging.** The first call has no token; each answer's `next_page_token` is sent
back unchanged for the next. An empty token ends the walk. A page holds at most
`serve.maxBrowseLimit` files.

**The token** is the catalogue epoch followed by the engine's cursor:

| Engine | Cursor | Goes stale when |
|---|---|---|
| memory | index layout number + record id | the name index is rebuilt, which renumbers the records |
| MySQL / MariaDB | last `files.id` read | never |
| MongoDB | last `_id` read | never |

**Reset.** A token of another epoch (the server restarted), or a cursor the
engine can no longer continue from, answers `reset` with no files. That is an
answer, not an error: the caller starts again. A token too short to hold an
epoch was never issued and is refused as `invalid_argument`.

**Not a snapshot.** Clients log in and out while a walk runs. A file may be
missed or returned twice. The mirror is built to tolerate that.

## Who may call

`serverSearch.mode` decides.

**`allowlist` (default).** Only the servers under `serverSearch.peers`. Two
operators agree on a token and each puts the other's URL and that token in its
config. The token is sent as a bearer token and compared in constant time; one
token serves both directions of the pair. Nothing is advertised.

**`gossip`.** As above, and additionally any server the gossip peer table has
admitted may call without a token, from the address gossip knows it by. The
service is then advertised to other servers (see below), and the servers that
advertise theirs are called. This is open to anyone who runs a server.

A caller that presents a token is judged by the token alone: a wrong one is
refused even from an admitted address.

Before either check, a caller the access filter blocks is refused, and
`serve.rateLimit.perIPPerMinute` applies by address. After it,
`perPeerPerMinute` applies to the admitted server.

### Advertisement (gossip mode)

A server in gossip mode tells other servers where the service is, in the frames
they already exchange:

| What | Value | Where |
|---|---|---|
| `ST_SERVER_SEARCH` | tag `0xA0`, string: base URL | extended `OP_SERVER_DESC_RES` |
| `ST_SERVER_SEARCH_FP` | tag `0xA1`, string: `sha256/<base64>` SPKI pin | extended `OP_SERVER_DESC_RES`, with TLS |

The tags come after the ones every reader knows. Both eMule trees walk that tag
list by id and skip one they do not know (`srchybrid/UDPSocket.cpp`, eMuleQt
`core/server/ServerList.cpp`). The `ST_VERSION` string is unchanged, so an
eserver still reads 17.7 or above, and the interop suite passes against eserver
17.14 with the tags present.

**No flag bit is sent.** The contract reserves `FlagServerSearch` (`0x20000`)
for the UDP flags word, and eNode-go never sets it: measured against eserver
17.14, a peer that sets that bit is still held and pinged, but eserver answers
every peer-list request with an empty list from then on, so the peer drops out
of the mesh (`TestGossipPropagatesThroughEserver`). The tag alone marks a server
that offers the service.

**A discovered server is dialled at its gossip address.** The URL in the tag is
the peer's own claim. Its port, host header and TLS name are used, but the
connection always goes to the IP gossip verified, so a server cannot point this
one at a third party. A URL that is not plain `http(s)://host[:port][/path]` is
ignored. A peer that stops sending the tags, or stops being admitted, is no
longer called and its mirrored files are dropped.

### Certificates

A self-signed certificate is enough. The fingerprint is logged at startup:

```
server search: certificate fingerprint sha256/… (give it to peers as serverSearch.peers[].fingerprint)
```

A configured peer with a `fingerprint` is trusted by that key and by nothing
else; without one its certificate is verified against the system's authorities.
In gossip mode the advertised fingerprint is pinned the same way.

## Asking other servers

Both halves below are off by default.

### Live search (`serverSearch.search.enabled`)

On a client's TCP search the peers are asked in parallel, each within
`search.timeoutMs`, alongside the storage query and the catalogue daemons. The
answer waits for the slowest of them, never past the timeout.

- **What is sent** is the part of the search tree a keyword query can carry: the
  keywords on the AND path, exclusions, type and size bounds. An OR branch
  cannot be sent, so every file that comes back is checked against the whole
  tree before it is used.
- **Cache.** One peer's answer to one query is kept for
  `search.cache.ttlSeconds`.
- **Failures.** A peer that answers `unavailable`, `unimplemented`,
  `unauthenticated` or `permission_denied` is left alone for 30 seconds. A
  timeout is counted and nothing else.
- **UDP searches never call a peer.** They are answered from the mirror alone,
  so one datagram cannot cost a call to every peer.

### Mirror (`serverSearch.mirror.enabled`)

A background walk per peer copies its catalogue into memory, and searches are
then answered from the copy without calling the peer.

1. `GetServerInfo`, then `BrowseFiles` from an empty token, `mirror.pageSize`
   files a call, waiting the peer's `browse_min_interval_seconds` between calls.
2. Every file read is stamped with the walk's number.
3. On `reset` the walk restarts under a new number and deletes nothing. Five
   resets in one round give up until the next.
4. When a walk completes, the peer's files that walk did not stamp are removed.
   That is the only way a file leaves: it stays until a whole later walk
   completes without it.
5. The next walk starts `mirror.intervalMinutes` later. A walk that failed is
   tried again after ten seconds, then after twice as long for every further
   failure in a row, up to five minutes, and never later than the interval.

**Bounds.** The mirror holds at most `mirror.maxFiles` files across all peers.
When a peer's catalogue does not fit, the mirror is marked trimmed for that
peer and the peer is still asked live on a search (when live search is on),
because the copy cannot answer for it alone.

**Staleness.** A peer no walk of which completed for `mirror.staleHours` loses
its copy.

**Not persisted.** The mirror is rebuilt after a restart. Until the first walk
of a peer completes, that peer is asked live.

### What a client sees

Files from other servers are ordinary eD2K rows: a hash, a name, a size, the
media tags and source counts. They follow the server's own files and the
catalogue rows in the answer.

- **No source is attached.** The client finds sources the way it does for any
  file the server has none for: global source queries, Kad, source exchange.
- **Every client gets them**, whether or not it asked for torrent and Usenet
  rows: they are real eD2K files.
- **The server's own file wins.** A file a local user shares is answered with
  the local row and its real sources.
- **Counts are never added up.** The same file from several servers shows the
  largest count. A count from another server is capped at 99, as a catalogue
  row's is.
- **They are not counted** in the file total the server advertises.

A peer is not trusted with the shape of what it sends: a file without a 16-byte
hash, a name or a size is dropped, and a name is cut to 255 bytes.

## Privacy

The rule is enforced in four places.

1. **The contract.** `ServerFile` has no field that could identify a client, and
   `enodemeta` has a test that fails when a field is added.
2. **The engines.** `BrowseFiles` returns files with `SourceID` and `SourcePort`
   zeroed.
3. **The service.** `toServerFile` is the one place a stored file becomes an
   answer, and it copies only descriptive fields.
4. **A test on the wire.** `TestAnswersIdentifyNoClient` marshals real answers
   and checks that no client's address, port, id or user hash occurs in the
   bytes.

**What a count reveals.** `sources` is how many of this server's users share a
file. A count of one says that exactly one user does, and not which.

**What the mirror holds.** Other servers' files only, with no client and no
source. It is never served to another server.

## Configuration

```yaml
serverSearch:
  enabled: false
  mode: allowlist              # allowlist | gossip
  listen: 0.0.0.0:4673
  advertiseURL: ""             # gossip mode; "" derives it
  allowInsecureAuth: false
  trustForwardedFor: false
  tls: { certFile: "", keyFile: "" }
  serve:
    search: true
    browse: true
    maxSearchLimit: 200
    maxBrowseLimit: 1000
    browseMinIntervalSeconds: 1
    cache: { maxEntries: 500, ttlSeconds: 300 }
    rateLimit: { perIPPerMinute: 120, perPeerPerMinute: 600 }
  peers: []                    # - { url, token, fingerprint }
  search:
    enabled: false
    timeoutMs: 1500
    maxResults: 50
    cache: { maxEntries: 1000, ttlSeconds: 300 }
  mirror:
    enabled: false
    intervalMinutes: 60
    maxFiles: 500000
    pageSize: 1000
    staleHours: 24
```

A peer entry without a `url` may call in but is never called. Changing anything
in this section needs a restart.

The server refuses to start when the section is enabled and

- `mode` is neither `allowlist` nor `gossip`;
- `mode` is `gossip` and `gossip.enabled` is off;
- `listen` is not `host:port`, or only one of `tls.certFile` / `tls.keyFile` is set;
- a peer has neither `url` nor `token`, or has no `token` in `allowlist` mode;
- two peers share a token (a token says which peer is calling);
- a peer's `fingerprint` is not `sha256/…`, or is set for a URL that is not `https`;
- a token would be sent to a peer over plain `http` outside loopback, without
  `allowInsecureAuth`;
- peers have tokens, the listener is not on loopback, there is no `tls`, and
  `allowInsecureAuth` is off;
- a limit is negative or above its ceiling (`maxSearchLimit` 1000,
  `maxBrowseLimit` and `mirror.pageSize` 2000).

### Example: two servers, tokens

Server A (`a.example.org`):

```yaml
serverSearch:
  enabled: true
  tls: { certFile: data/search.crt, keyFile: data/search.key }
  peers:
    - url: https://b.example.org:4673
      token: "one-long-random-string"
      fingerprint: "sha256/<B's fingerprint>"
  search: { enabled: true }
  mirror: { enabled: true }
```

Server B is the mirror image, with A's URL and fingerprint and the same token.

## Errors

| Code | When | `msg_code` |
|---|---|---|
| `unauthenticated` | No token, or one the server does not know, and not an admitted server | `serversearch.unauthorized` |
| `permission_denied` | The access filter blocks the caller | `serversearch.unauthorized` |
| `resource_exhausted` | Rate limit | `ratelimit.exceeded` |
| `invalid_argument` | `SearchFiles` without a keyword | `search.query_required` |
| `invalid_argument` | A query over 256 bytes | `search.query_too_long` |
| `invalid_argument` | A page token that was never issued | `serversearch.cursor_invalid` |
| `unimplemented` | `serve.search` is off | `search.disabled` |
| `unimplemented` | `serve.browse` is off | `serversearch.browse_disabled` |
| `unavailable` | The storage engine failed | `search.unavailable` |

The codes are translated in `locales/*.json`. `serversearch.disabled` is
reserved for a server that has the service off but still answers.

## Trying it

With the listener on loopback without TLS:

```sh
grpcurl -plaintext -H 'Authorization: Bearer one-long-random-string' \
  -import-path enodemeta/proto -proto enode/meta/v1/server.proto \
  127.0.0.1:4673 enode.meta.v1.ServerSearch/GetServerInfo

grpcurl -plaintext -H 'Authorization: Bearer one-long-random-string' \
  -import-path enodemeta/proto -proto enode/meta/v1/server.proto \
  -d '{"query":"debian","limit":20}' \
  127.0.0.1:4673 enode.meta.v1.ServerSearch/SearchFiles

curl -s -H 'Authorization: Bearer one-long-random-string' \
  -H 'Content-Type: application/json' -d '{"limit":100}' \
  http://127.0.0.1:4673/enode.meta.v1.ServerSearch/BrowseFiles
```

## Dashboard

The admin page shows a **Server search** section when the service is on, and
`/stats.json` carries it as `serverSearch`: the mode, the listener URL and the
certificate fingerprint, what was served (searches, browse pages, files,
resets), what was refused (not accepted, rate limited), and one line per peer
with its state, whether it is configured or came from gossip, its mirror state
and its live-call counters. See
[admin-status-dashboard.md](admin-status-dashboard.md).

## Testing

| Test | What it pins |
|---|---|
| `storage/browse_files_test.go` | The walk returns every shared file once on all three engines; the memory cursor dies with the index layout |
| `storage/mirror_test.go` | Sweep is how a file leaves; counts take the larger; the cap; no source kept |
| `serverlink/service_test.go` | Paging, filters, reset, both modes of admission, rate limits, certificate pinning, **no client identity on the wire** |
| `serverlink/searcher_test.go` | Live search and its cache, post-filtering, backoff, the mirror following a peer, a full mirror, reset, discovery |
| `ed2k/serversearch_advert_test.go` | The numbers match the contract; the description reply carries and loses the advert |
| `config/serversearch_config_test.go` | Defaults and every refusal above |
| `cmd/enode/serversearch_test.go` | Two real servers: one serves, the other mirrors it |

```sh
go test ./storage ./serverlink ./config ./ed2k ./admin ./cmd/enode
ENODE_INTEGRATION=1 go test ./storage -run 'BrowseFiles'   # MySQL and MongoDB, needs Docker
```

## By design / deferred

- **The catalogue daemons' rows are not served.** A server that wants torrent,
  Usenet or Kad rows runs its own daemons.
- **Other servers' files in `MetaApi.Search` are opt-in.** With
  `metaApi.search.servers` on they are the `META_NETWORK_SERVERS` network,
  together with this server's own files. See
  [meta-api.md](meta-api.md#the-servers-network). That answer is built by
  `serverlink/catalog.go` from the same mirror and the same peers, and is no
  part of what `ServerSearch` serves: a peer's files are never passed on to
  another server.
- **The mirror is not persisted**, and is not shared between instances.
- **No reload.** The section is restart-only, like `metaSearch` and `metaApi`.
- **A search cannot be forwarded.** A server asks its own peers and nobody
  else's: there is no hop count because there is no second hop.
