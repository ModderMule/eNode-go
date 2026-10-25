# Server <=> Client Communication (OP_* Meanings)

This document explains the main `OP_*` operation codes used by `eNode-go` and their expected direction.

## Protocol Basics

- Transport protocols:
  - `PR_ED2K (0xe3)`: normal eD2K packets
  - `PR_ZLIB (0xd4)`: compressed payloads
  - `PR_EMULE (0xc5)`: eMule-specific protocol family
  - `PR_NAT (0xf1)`: NAT traversal UDP protocol family
- TCP packet format (simplified): `protocol(1) + size(4) + opcode(1) + payload`
- UDP packet format (simplified): `protocol(1) + opcode(1) + payload`
- NAT UDP packet format: `protocol(1) + size(4, little-endian) + opcode(1) + payload`

## TCP OP Codes

| OP constant | Hex | Direction | Meaning |
|---|---:|---|---|
| `OP_LOGINREQUEST` | `0x01` | Client -> Server | Client login/session registration. |
| `OP_HELLO` | `0x01` | Server -> Client (handshake check client path) | Basic hello packet; same numeric code as login in different context. |
| `OP_HELLOANSWER` | `0x4c` | Peer -> Server/client helper | Response to `OP_HELLO` with node info/tags. |
| `OP_GETSERVERLIST` | `0x14` | Client -> Server | Request known server list. |
| `OP_OFFERFILES` | `0x15` | Client -> Server | Submit shared file/source list. A record is indexed under `(hash, size)` and one with no usable size is refused — see [File identity](#file-identity). Capped per client by `files.softLimit` / `files.hardLimit` — see [Per-client publish limits](#per-client-publish-limits). |
| `OP_GETSOURCES` | `0x19` | Client -> Server | Request sources for a file. |
| `OP_GETSOURCES_OBFU` | `0x23` | Client -> Server | Obfuscated source request variant. |
| `OP_SEARCHREQUEST` | `0x16` | Client -> Server | Search query request. |
| `OP_QUERY_MORE_RESULT` | `0x21` | Client -> Server | Next page of the last search. Empty payload — the client's "More" button sends only the opcode (`srchybrid/SearchResultsWnd.cpp:1282`), so the remaining results are held per connection: at most `tcp.moreResults.maxRows` rows (default 510, two pages; 0 = no paging) for `tcp.moreResults.ttlSeconds` (default 300; an idle session's rows are dropped by its 5-minute status ticker, so up to 5 minutes later). A More after that gets an empty final page. |
| `OP_DISCONNECT` | `0x18` | Client -> Server | Client is leaving. Releases the session, its LowID and its storage row at once, instead of waiting for the read loop to see a FIN — or, for a socket that dies without one, for `disconnectTimeout`. |
| `OP_CALLBACKREQUEST` | `0x1c` | Client -> Server | Ask server to callback a LowID client. |
| `OP_SERVERMESSAGE` | `0x38` | Server -> Client | Human-readable server message. |
| `OP_SERVERSTATUS` | `0x34` | Server -> Client | Current server counters/status. |
| `OP_IDCHANGE` | `0x40` | Server -> Client | Assign/update client ID and flags, and report the IPv4 the server observes the client on. |
| `OP_SERVERLIST` | `0x32` | Server -> Client | Response with known servers. |
| `OP_SERVERIDENT` | `0x41` | Server -> Client | Server identity/tags response. |
| `OP_FOUNDSOURCES` | `0x42` | Server -> Client | Source list for requested file. |
| `OP_FOUNDSOURCES_OBFU` | `0x44` | Server -> Client | Obfuscated found-sources response (adds per-source obfuscation settings byte). |
| `OP_SEARCHRESULT` | `0x33` | Server -> Client | Search results list, followed by a single "more results available" byte. |
| `OP_CALLBACKREQUESTED` | `0x35` | Server -> LowID client | Notify LowID client to connect back. |
| `OP_CALLBACKFAILED` | `0x36` | Server -> Client | Callback target unavailable/failure. |
| `OP_NAT_CALLBACKREQUESTED` | `0x37` | Server -> LowID client | Lugdunum NAT callback notice, TCP fallback for UDP `0xa7`; see [`lugdunum-nat-callback.local.md`](lugdunum-nat-callback.local.md#enode-go). |
| `OP_NAT_WAKE` | `0x46` | Server -> Client | PR_NAT wake-up: `families(uint8)` (`0x01` IPv4, `0x02` IPv6). Sent to a session that set login bit `0x200000` when a SYNC2 names it and it has no registration; the client answers with one PR_NAT `REGISTER` per family. See [`pr-nat-rendezvous-spec.md`](pr-nat-rendezvous-spec.md#waking-a-local-target). |
| `OP_GETSOURCES_IPV6` | `0x24` | Client -> Server | IPv6 tag-block source query (opt-in); payload as `OP_GETSOURCES2`. |
| `OP_FOUNDSOURCES_IPV6` | `0x25` | Server -> Client | IPv6 tag-block source response (per source: `id+port+tagCount+tags`). |
| `OP_CALLBACKREQUESTED_IPV6` | `0x26` | Server -> v6-capable client | IPv6 form of `OP_CALLBACKREQUESTED`; sent when the requester has no usable IPv4 but a reachable public IPv6. |

### File identity

**A file is identified by `(hash, size)`, not by the hash alone.** All three storage
engines key on the pair, and an offer carrying a hash that is already indexed at a
different size creates a second record rather than overwriting the first.

This is the protocol's own answer, not a local convention. eserver 17.3 (2005-02-15,
`lugdunum-eserver/docs/kiten-20071012.txt:189-190`):

> Make sure the size of a published file matches the known file size. A lot of buggy or
> malicious clients try to mislead the network.
> Change the ed2k protocol to let clients tell us the size of the files they are
> downloading, not only the hash.

and 17.14 at `:142` — *"Changes in size conflicts (when same hash but different sizes are
given)"*. That 17.3 protocol change is why TCP `OP_GETSOURCES` carries the size
unconditionally (`srchybrid/DownloadQueue.cpp:1350-1357` — a 20-byte payload, or 28 when a
zero `uint32` marks a 64-bit size following) and why `SRV_UDPFLG_EXT_GETSOURCES2` picks the
sized `OP_GLOBGETSOURCES2 (0x94)` over the sizeless `OP_GLOBGETSOURCES (0x9a)`. Both client
trees agree on what "the same file" means: `CFileIdentifierBase::CompareStrict` compares
MD4 **and** size **and** AICH (`srchybrid/FileIdentifier.cpp:84-93`), and eMule moved its own
Kad index off a hash-only key for exactly this reason in 0.49a (`changelog_full.txt:2164`,
*"Same hashes (files) which have different filesizes are now properly stored separatly
instead overwriting eachother"*).

Nothing in either client tree claims a hash uniquely determines a size. The clients do key
their *local* known-file maps by MD4 alone, but a local map is not an index of a hostile
network — which is the distinction eserver 17.3 drew.

**Where each engine keys it.** MySQL: `UNIQUE KEY hash_size (hash,size)`, whose leading
`hash` column also serves the hash-only lookups (`misc/enode.sql`). MongoDB: a unique compound index on
`{hash, size}`, with sources identified by `(file_hash, file_size, client_hash)`. The
memory engine: `storage.fileMapKey`, a 24-byte key of the hash followed by the size
big-endian.

**The memory engine's source lists stay keyed on the hash alone**, because
`OP_GLOBGETSOURCES (0x9a)` carries bare hashes with no size and has to stay an O(1)
lookup — the same reason MySQL keeps `hash` first in the unique pair. Each source
records the size it was offered at, so `GetSources(hash, size)` and the search counters
see only that size's sources, as MySQL and MongoDB do; the size-less 0x9a lookup gets
them all. Sources come back newest offer first (a re-offer counts as new), matching the
DB engines' `time_offer DESC`.

**A zero-size offer is refused.** If `FT_FILESIZE` is absent, or present but not an
integer, the parsed size is `0` and the record is dropped before it reaches storage, with
one `offer files zero size` info line per packet rather than per record. Such a file could
never be served — a client only asks for sources by `(hash, size)`, and eMule discards a
zero-size search result outright (`srchybrid/SearchList.cpp:355`) — so it would sit in the
index for good, searchable and unservable. Dropped records are charged against neither
publish limit.

**Open: the pre-17.3 size-less `OP_GETSOURCES` is not answered.** The opcode was
originally just `<HASH 16>` (`srchybrid/opcodes.h:164` still documents it that way); the
size was appended by the 17.3 change above. `parseGetSources` (`ed2k/server_runtime.go`)
requires the size, so a request without one is dropped with
`get sources parse failed … err=buffer: out of bounds` and the client gets no reply.
Production logs (2026-10-13) show two shapes of this:

- Bursts of about 15 failures from one client every 300 s — eMule's
  one-frame-of-15-requests cadence (`srchybrid/DownloadQueue.cpp:1377-1387`), so most
  likely an old eMule-derived client sending the bare 16-byte hash. The `uint32` read
  fails.
- A client that also offers zero-size files failing on `OP_GETSOURCES_OBFU`. Probably a
  literal `uint32` size of `0`, which we read as the large-file marker and then fail on
  the missing `uint64`. This is inferred from the correlation, not confirmed — both
  branches log the same message.

Neither affects current eMule, eMuleQt or eMuleAI, which always send the size. A fix, if
we want these clients served:

1. In `parseGetSources`, treat "no bytes after the hash" and "zero `uint32` with nothing
   after it" as *size unknown* instead of an error; keep failing on a truncated size
   (1-3 or 1-7 trailing bytes).
2. For size unknown, answer from `Storage.GetSourcesByHash(hash)` — the lookup the
   size-less UDP `OP_GLOBGETSOURCES (0x9a)` already uses — in `handleGetSources` and
   `handleGetSourcesIPv6`, still behind `withheldHash`.
3. Give the two parse failures distinct `err=` texts so the log tells them apart.

The cost is the one 17.3 set out to remove: a hash-only answer mixes the sources of every
size offered under that hash, so a client can be handed sources for a different file. That
is already true of 0x9a. Unverified: what eserver 17.14/17.15 does with a 16-byte
`OP_GETSOURCES` — worth a `tests/interop` case before implementing.

### Login precondition

Every TCP opcode except `OP_LOGINREQUEST (0x01)` and `OP_DISCONNECT (0x18)` requires a
completed login. A session that has not logged in is sent one `OP_SERVERMESSAGE` —

```
ERROR : You must log in before sending requests to this server.
```

— and dropped, with `reason=not-logged-in` in the session-closed log line. Opcodes that
are not handled at all (see the table below) are refused the same way before login rather
than being logged and ignored, because a client that has not logged in has no business
sending them either.

The rule is deny-by-default: `handleED2K` exempts the two opcodes above and gates the rest,
so an opcode added to the dispatcher is gated unless someone deliberately exempts it.

**Why.** `handShake` is the only place a session's identity is established. Before it runs
the server has nothing: `{ID: 0, Port: 0, Hash: nil, StoreID: 0}`. `OP_OFFERFILES` is the
opcode that made this matter, because it is the only one that *writes* to the index, and
what it wrote under that identity could never be taken back:

- **memory engine** (the default) — sources dedupe on `(ID, Port)`, so every pre-login
  offer from every socket collapsed into one `{0, 0}` row per hash — served to real
  clients, which can do nothing with an address of `0:0`, and occupying slots in the
  255-entry wire cap. Nothing reclaimed them: the teardown path calls `Storage.Disconnect`
  only for a session that was logged in, and the memory engine's `CleanupStale` cannot
  expire a source at all, because a source carries no timestamp. They lived for the
  lifetime of the process.
- **MongoDB** — the same, keyed on a nil `client_hash`, plus `source_id: 0, source_port: 0`
  written into the file document.
- **MySQL** — the mild case. The source row fails the `sources_ibfk_2` foreign key on
  `id_client = 0` and is dropped with one error line per offered record, leaving an orphan
  `files` row that `CleanupStale` reaps.

A fourth consequence has since been closed at the storage layer instead of here: the memory
engine used to key a file on its hash alone and overwrite the whole record, so *any* offer
— anonymous or not — could rewrite the `Size` of an already-indexed hash and blackhole
every later source lookup for it. Files are keyed on `(hash, size)` now; see
[File identity](#file-identity).

**No conforming client is affected.** Both reference trees send their first request only
once the login round trip has completed: `srchybrid/ServerConnect.cpp:227-228` calls
`SendListToServer()` from the `CS_CONNECTED` branch, and
`eMuleQt/src/core/files/SharedFileList.cpp:652-653` returns early unless
`ServerConnect::isConnected()`. `OP_GETSERVERLIST` is sent from that same post-login branch
in both. A client that pipelines its login and its first request into one TCP segment is
also fine: dispatch is sequential per connection and the login is processed to completion
before the next opcode is read.

The one thing this does refuse is a third-party tool that connects and asks for the peer
list *without* logging in. No surveyed client does that, but it is the one behaviour here
that something external could have depended on.

### Per-client publish limits

How many files a single client may publish, and what happens when it tries to publish more.
Both are configured under `files:` in `enode.config.yaml`, enforced in `handleOfferFiles`, and
advertised on the wire so a client sees the numbers it is actually held to. For what a
given cap costs in RAM at scale see [`memory-footprint.local.md`](memory-footprint.local.md) §4.

They are **per-client publish caps, not server capacity figures** — worth stating because
in `OP_GLOBSERVSTATRES` they sit next to `maxusers` and read like capacity. Both come from
Lugdunum's eserver, whose documentation is vendored at
`lugdunum-eserver/docs/kiten-20071012.txt`:

> **`softLimit`** (`:462`) — *"If a client tries to publish more than softLimit files, the
> server sends him a WARNING message and ignores files in excess. Default value : 1000"*

> **`hardLimit`** (`:349`) — *"If a client tries to publish more than hardLimit files, the
> server disconnects him (before receiving the whole list). That is to save bandwidth,
> because some lazy people share all their files. Default value : 4000"*

The hard limit is therefore not simply a larger soft limit. The two count different
things:

| | soft limit | hard limit |
|---|---|---|
| **What it counts** | the distinct files a session sources at a time | the records one `OP_OFFERFILES` packet declares |
| **What it is** | a quota on the index | an abuse response |
| **What it protects** | server RAM — how large the index grows | server bandwidth and CPU — receiving a huge list at all |
| **Effect** | new files past it are ignored; the client stays connected | the packet is refused whole and the session is closed |
| **Client is told** | one `WARNING` message per session | one `ERROR` message, then the close |
| **eserver default** | 1000 | 4000 |
| **eNode-go default** | 10000 | 20000 |

eserver's accounting reflects the split: it publishes both in its stats line
(`eserver-17.14-strings.txt:20339`) but counts hard-limit drops with the *refusals*,
alongside blacklisting and ipfilter (`:20958`).

**The hard limit is on one packet.** An `OP_OFFERFILES` that declares `hardLimit` records
or more is refused: nothing of it is parsed or stored, the client is sent the `ERROR`
message and the session is closed. That is Lugdunum's "before receiving the whole list".
Both eMule trees cap a packet at 200 files whatever the server's limits
(`srchybrid/SharedFileList.cpp:832-834`, `eMuleQt/src/core/files/SharedFileList.cpp:54,880`;
a server's soft limit can only lower that) and send one packet a minute until the whole
share is registered (`:1229-1236`). So a conforming client never reaches the hard limit,
however much it shares, and only a broken or abusive one is disconnected. Keep `hardLimit`
above 200.

**The soft limit is on the session's files.** It is held against the number of distinct
files the session sources now, which storage keeps per session anyway to release them on
disconnect (`Engine.OfferedCount`). Two consequences:

- A file the session already sources can always be offered again and costs nothing. A
  client republishes a file when a download completes, so its complete flag stays current
  even for a session at its limit.
- A new file past the limit is skipped, and the first time that happens the client is
  sent the `WARNING` message.

Most packets need one in-memory lookup for this: while everything a packet offers would fit
under the limit even if all of it were new, nothing has to be told apart. Only a packet that
could cross the limit asks storage which of its files the session already sources
(`Engine.HasOffered`), which on MySQL and MongoDB is one indexed query.

Until 2026-10 both limits counted every *record* a session sent, re-offers included, and the
hard limit was that running total. A client sharing 50,000 files reached 20,000 records
about 100 minutes in, was dropped, reconnected and started over, for as long as it ran; and
a client that re-offered its files ran into the soft limit with far fewer files than it
allows.

**Configuration:**

```yaml
files:
  softLimit: 10000   # distinct files per session: warn once, ignore new ones; 0 = unlimited
  hardLimit: 20000   # records per packet: message, then disconnect;         0 = unlimited
```

`0` means unlimited on either key, the convention `tcp.maxConnections` already uses. An
absent key takes the default above; the fields are `*int` precisely so an explicit `0` can
be told from an omitted key. A negative value is rejected at load. `hardLimit` may be below
`softLimit`: one is a packet size and the other a session total, so neither bounds the
other. (It was a load error while both counted a session's records.)

**On the wire:** both are published at `OP_GLOBSERVSTATRES (0x97)` payload offsets **+16**
and **+20**, read positionally by eMule (`srchybrid/UDPSocket.cpp:337-342,403-404`) and
persisted in `server.met` as `ST_SOFTFILES 0x88` / `ST_HARDFILES 0x89`. Only `softFiles` is
ever used behaviourally — it clamps the per-packet offer count. `hardFiles` is stored,
persisted and displayed in both trees and never compared against anything: it is the
server's business alone. The advertised values and the enforced values come from the same
two config keys.

**What a client sees.** Over the soft limit, once per session:

```
WARNING : This server accepts 10000 shares per client. Some of your shares are ignored.
```

eserver's own text, verbatim (`eserver-17.14-strings.txt:20786`). For a packet at the hard
limit, one message then the close:

```
ERROR : This server accepts at most 20000 shares per client. Closing the connection.
```

That one is our divergence: eserver drops silently, having a `MsgSOFTLIMIT` keyword with no
`MsgHARDLIMIT` counterpart. A client cannot tell a silent drop from any other mid-session
close, so the user would have no way to learn why they keep being disconnected.

**Behaviour worth knowing:**

- **Which files survive the soft trim** is "whichever arrived first", and that is right
  rather than accidental: eMule sorts its offer by upload priority before truncating to the
  packet cap (`SharedFileList.cpp:814-828`), so what survives is the client's own
  highest-priority share. Anything skipped is gone for that session — the client has
  already marked it published and will not re-offer it.
- **The count follows what the session sources**, not what it sent. A record the server
  refuses (no size, a meta pseudo-hash, the content filter) is not counted. On the memory
  engine a file is counted by its hash, so the same hash at two sizes is one file; on MySQL
  and MongoDB, where a source belongs to a `(hash, size)` row, it is two.
- **A reconnect starts from zero.** On the memory engine `Disconnect` deletes the client's
  sources outright. On MySQL and MongoDB the rows stay, offline, and a republish revives
  them; only the ones the new session has offered count against it.
- **A large sharer keeps its session.** A client sharing 50,000 files at the defaults
  publishes its first 10,000, is warned once, and stays connected with those 10,000
  indexed. Raise `softLimit` to index more of it; docs/memory-footprint.local.md §4 says what
  that costs.
- **`hardLimit` is advertised but means something else to the server now.** Clients store
  and display it and compare it against nothing, so advertising a per-packet figure in the
  `hardFiles` field changes nothing for them.

**Where the code is:**

| What | Where |
|---|---|
| Config keys, defaults, validation | `config/config.go` — `FilesConfig`, `setDefaults` |
| Enforcement | `ed2k/server_runtime.go` — `handleOfferFiles`, `withinSoftLimit`, and the `softLimitWarned` / `hardLimitHit` fields on `tcpClient` |
| Files per session | `storage/factory.go` — `Engine.OfferedCount`, `Engine.HasOffered` |
| Login gate | `ed2k/server_runtime.go` — `requireLogin`, and the exemption switch at the head of `handleED2K` |
| Message texts | `ed2k/server_runtime.go` — `msgSoftFileLimit`, `msgHardFileLimit`, `msgNotLoggedIn` |
| Advertising | `ed2k/udpoperations.go` — `BuildGlobServStatResPacket`, `UDPConfig.SoftFiles/HardFiles` |
| Wiring | `cmd/enode/main.go` — both runtime configs, from one accessor each |
| Tests | `ed2k/offer_limits_test.go`, `ed2k/offer_prelogin_test.go`, `config/file_limits_test.go`, `storage/offered_contract_test.go` |

### Search paging

`OP_SEARCHRESULT` now ends with one "more results available" byte, and eMule's contract for
it is exact (`srchybrid/SearchList.cpp:266-277`): it must be the *only* trailing byte and
its value must be `0x00` or `0x01`. Two trailing bytes, or a `0x02`, are logged as
unexpected AddData and the flag is left false — so the client's More button never appears.
The byte is therefore always emitted, `0x00` meaning "that was everything".

Results are paged at `storage.MaxSearchPage` (255) per packet, with the remainder held on
the connection and served by `OP_QUERY_MORE_RESULT`. The engines' fetch ceiling is
`storage.MaxSearchResults` (1000): previously it was also 255, i.e. the same number as the
page size, so a deeper result set was silently truncated with no way for a client to ask
for the rest.

IPv6 is additive and opt-in; classic packets are byte-identical to before. See
[`ipv6-client-implementation-spec.md`](ipv6-client-implementation-spec.md) for the
full IPv6 wire formats (login `CT_MOD_IP_V6 0xAE` tag, the `0xFFFFFFFF` source
sentinel, `CT_MOD_SVR_IP_V6 0xAF` in `OP_SERVERIDENT`, and `SRV_*FLG_IPV6 0x4000`).

### Client -> Server TCP opcodes not handled

These reach the default branch in `handleED2K` (`ed2k/server_runtime.go`) and are
logged, not answered. None of them breaks a session:

| OP constant | Hex | Why it is safe to ignore |
|---|---:|---|
| `OP_SEARCH_USER` | `0x1a` | Never sent by the surveyed clients to a server. |

`OP_DISCONNECT (0x18)` and `OP_QUERY_MORE_RESULT (0x21)` used to be listed here. Both are
now handled — see the TCP table above and the search-paging note below.

Being unhandled is not the same as being free to send: an unhandled opcode is logged and
ignored only for a session that has logged in. Before login it is refused like any other
gated opcode — see [Login precondition](#login-precondition).

## UDP OP Codes

| OP constant | Hex | Direction | Meaning |
|---|---:|---|---|
| `OP_GLOBGETSOURCES` | `0x9a` | Client -> Server | UDP source query by hash. |
| `OP_GLOBGETSOURCES2` | `0x94` | Client -> Server | UDP source query with hash+size. |
| `OP_GLOBSERVSTATREQ` | `0x96` | Client -> Server | UDP server stats request. |
| `OP_SERVERDESCREQ` | `0xa2` | Client -> Server, and Server -> Server | UDP server description request. Also *sent* by us to a gossip peer as the admission probe, and its `0xa3` reply parsed — see [`server-gossip.md`](server-gossip.md). |
| `OP_GLOBSEARCHREQ` | `0x98` | Client -> Server | UDP search request. |
| `OP_GLOBSEARCHREQ2` | `0x92` | Client -> Server | UDP search request, payload identical to `0x98` (bare search tree, no tag block). Sent by a client that believes we do ext-get-files but not large files. Answered by the same handler as `0x98`. |
| `OP_GLOBSEARCHREQ3` | `0x90` | Client -> Server | Extended UDP search request (tree/tags). |
| `OP_GLOBFOUNDSOURCES` | `0x9b` | Server -> Client | UDP source response. |
| `OP_GLOBSERVSTATRES` | `0x97` | Server -> Client | UDP server stats response. |
| `OP_SERVERDESCRES` | `0xa3` | Server -> Client | UDP server description response. |
| `OP_GLOBSEARCHRES` | `0x99` | Server -> Client | UDP search results response. |
| `OP_GLOBGETSOURCES_IPV6` | `0xa5` | Client -> Server | IPv6 tag-block UDP source query (opt-in); payload as `OP_GLOBGETSOURCES2`. |
| `OP_GLOBFOUNDSOURCES_IPV6` | `0xa6` | Server -> Client | IPv6 tag-block UDP source response. |
| `OP_NAT_CALLBACKREQUEST` | `0xa6` | Client -> Server | Lugdunum NAT callback request, obfuscated only: `<targetID 4><requesterID 4>`. Same value as the row above, other direction. |
| `OP_NAT_CALLBACKREQUESTED_UDP` | `0xa7` | Server -> Client | Lugdunum NAT callback notice: `<requesterIP 4><requesterUDPPort 2><requesterID 4><cryptFlags 1>[<userHash 16>]`. Same value as `OP_SERVER_LIST_REQ_IPV6`, which only travels between servers. |
| `OP_SERVER_LIST_REQ` | `0xa0` | Server <-> Server | Gossip: "register me", `<ip 4><port 2>` + optional `<challenge 4>`. |
| `OP_SERVER_LIST_RES` | `0xa1` | Server <-> Server | Gossip: peer list, `<count 1>` then count × (`<ip 4><port 2>`). |
| `OP_SERVER_LIST_REQ2` | `0xa4` | Server <-> Server | Gossip: explicit list request, empty payload. |
| `OP_SERVER_LIST_REQ_IPV6` | `0xa7` | Server <-> Server | **eNode-go extension**: v6 list request, empty payload. |
| `OP_SERVER_LIST_RES_IPV6` | `0xa8` | Server <-> Server | **eNode-go extension**: `<count 1>` then count × (`<ipv6 16><port 2>`). |

The five gossip opcodes are only dispatched when `gossip.enabled` is set; otherwise they
reach the unknown-opcode log exactly as before. `0xa0`/`0xa1` are accepted only over the
obfuscated channel. See [`server-gossip.md`](server-gossip.md).

## NAT Traversal UDP OP Codes (`PR_NAT = 0xf1`)

`PR_NAT` is a UDP hole-punch rendezvous, **dual-stack**: the server stores up to two
candidates per client hash (one IPv4, one IPv6 — the observed source of each register)
and, when pairing, prefers IPv6 when both peers have a v6 candidate, else IPv4. All
endpoint fields are **big-endian**. IPv6 hole-punching is gated by `natTraversal.ipv6`
(default on, needs `ipv6.enabled`); when off, IPv6 `PR_NAT` datagrams are declined and
the family is IPv4-only. The registry is keyed by user hash and is **login-independent**:
`natTraversal.serverIndependent` (default on) makes the server pair two registered
clients regardless of which eD2K server (if any) they are on — cross-server / serverless
LowID↔LowID — and advertise it via `SRV_TCPFLG_NAT_RENDEZVOUS (0x40000)` in the TCP and
UDP flags plus a `ST_NAT_PORT (0x9d)` uint16 tag in `OP_SERVERIDENT`; when off, pairing is
restricted to clients logged into this server (`OP_NAT_FAILED` reason `0x03`).
`natTraversal.tcpWake` (default on) adds flag `0x200000` and the TCP wake-up
(`OP_NAT_WAKE`, above), so clients logged in here keep no standing registration. PR_NAT is
plaintext on every port, the obfuscated one included. Full protocol + byte-exact layouts:
[`pr-nat-rendezvous-spec.md`](pr-nat-rendezvous-spec.md).

| OP constant | Hex | Direction | Meaning |
|---|---:|---|---|
| `OP_NAT_REGISTER` | `0xe4` | Client -> NAT Server | Register/refresh client hash; server records the observed endpoint in its v4/v6 slot. |
| `OP_NAT_REGISTER` | `0xe4` | NAT Server -> Client | v4 register ACK with server endpoint (`port(2, BE) + ip(4, BE)`). |
| `OP_NAT_REGISTER_IPV6` | `0xec` | NAT Server -> Client | v6 register ACK with server endpoint (`port(2, BE) + ipv6(16)`). |
| `OP_NAT_SYNC2` | `0xe9` | Client -> NAT Server | Ask server to pair source hash with target hash (`srcHash(16)+connAck(4)+dstHash(16)`). |
| `OP_NAT_SYNC` | `0xe1` | NAT Server -> Client | v4 peer endpoint exchange (`peerIP(4, BE)+peerPort(2, BE)+peerHash(16)+connAck(4)`). |
| `OP_NAT_SYNC_IPV6` | `0xed` | NAT Server -> Client | v6 peer endpoint exchange (`peerIPv6(16)+peerPort(2, BE)+peerHash(16)+connAck(4)+version(1)`). |
| `OP_NAT_PING` | `0xe2` | NAT Server -> Client | NAT keepalive ACK ping (empty payload) after accepted keepalive. |
| `OP_NAT_FAILED` | `0xe5` | NAT Server -> Client | Pairing failed (`reason(1) + targetHash(16)`; reason `0x01` = target not registered, `0x02` = no common address family, `0x03` = rendezvous restricted — server-independent off and a peer not logged in here). |
| `OP_NAT_KEEPALIVE` | `0xe6` | Client -> NAT Server | NAT keepalive with NAT envelope; refreshes `lastSeen`, extends the matching eD2K session's read deadline (see below), and receives `OP_NAT_PING` when endpoint is registered. |
| keepalive (non-`PR_NAT`, legacy) | n/a | Client -> NAT Server | Legacy raw 1-byte UDP heartbeat; still accepted and receives `OP_NAT_PING` when endpoint is registered. |

## Payload Data Format

### Encoding Conventions

| Item | Format |
|---|---|
| Integer endian | Little-endian unless explicitly noted |
| `hash16` | Fixed 16-byte client/file hash |
| `string` | `uint16 length + bytes` |
| `tags` | `uint32 count`, then repeated tag entries (see `ed2k/buffer.go`) |
| `source entry` | `clientID(uint32) + clientPort(uint16)` |

### TCP Payloads (Implemented Here)

| OP | Direction | Payload Format |
|---|---|---|
| `OP_LOGINREQUEST` | Client -> Server (parsed) | `hash16 + clientID(uint32) + clientPort(uint16) + tags` |
| `OP_SERVERMESSAGE` | Server -> Client | `message(string)`. May carry several lines in one packet, CRLF-separated — see [Multi-line server messages](#multi-line-server-messages) below. |
| `OP_SERVERSTATUS` | Server -> Client | `clients(uint32) + files(uint32)` |
| `OP_IDCHANGE` | Server -> Client | `clientID(uint32) + tcpFlags(uint32) + primaryTCPPort(uint32) + observedClientIPv4(uint32)`. eMule's full documented layout (`srchybrid/Opcodes.h:182`); it lower-bounds the size only, reading the flags at size >= 8 and the observed IP at size >= 16. `primaryTCPPort` is annotated "unused" by the reference and ignored by both surveyed clients. `observedClientIPv4` is the address the socket arrived from — the only public-IPv4 source a LowID client has — and is `0` when the server has no routable IPv4 for the session (v6-only, or a value a client would reject as a LowID). Such a session is assigned a LowID as well — an address ending in `.0` packs into the LowID range, so it cannot be a HighID either — which keeps `clientID` and `observedClientIPv4` consistent. See [`ipv6-client-implementation-spec.md`](ipv6-client-implementation-spec.md) §2 and §3a. A client that set login bits `0x1000` (Lugdunum NAT callback) and `0x200` gets 24 bytes when `natTraversal.lugdunumCallback` is on: `+ obfuscationTCPPort(uint32) + clientTCPPort(uint32)`, and an odd LowID (every other LowID is even); see [`lugdunum-nat-callback.local.md`](lugdunum-nat-callback.local.md#enode-go). |
| `OP_SERVERLIST` | Server -> Client | `v4count(uint8) + repeated(serverIP(uint32) + serverPort(uint16))` [`+ v6count(uint8) + repeated(serverIPv6(hash16) + serverPort(uint16))`]. The trailing IPv6 block is appended only when IPv6 publication is on and a peer server has a public IPv6; it is pure trailing data after the self-terminating v4 count, so a v4-only client ignores it. See [`ipv6-client-implementation-spec.md`](ipv6-client-implementation-spec.md) §8. |
| `OP_SERVERIDENT` | Server -> Client | `serverHash(hash16) + serverIP(uint32) + serverPort(uint16) + tags`. Tags are `ST_SERVERNAME`, `ST_DESCRIPTION`, then optionally `CT_MOD_SVR_IP_V6 (0xaf, hash16)`, `ST_NAT_PORT (0x9d, uint16)`, and the two per-session reflection tags `CT_MOD_YOUR_IP` (`0xad`, hash16 — the IPv6 the server observes this client on, v6-connected sessions only) and `ST_IPV6_STATUS` (`0xab`, uint8 — the `IPV6ST_*` reachability bitfield). All are additive: eMule dispatches on the tag name and consumes unknown names by type, so a client that ignores them parses as before. See [`ipv6-client-implementation-spec.md`](ipv6-client-implementation-spec.md) §3a. |
| `OP_FOUNDSOURCES` | Server -> Client | `fileHash(hash16) + sourceCount(uint8) + repeated(source entry)` |
| `OP_FOUNDSOURCES_OBFU` | Server -> Client | `fileHash(hash16) + sourceCount(uint8) + repeated(source entry + obfSettings(uint8) [+ userHash(hash16) if obfSettings&0x80])` |
| `OP_SEARCHRESULT` | Server -> Client | `resultCount(uint32) + repeated(fileRecord)`; `fileRecord = fileHash(hash16) + sourceID(uint32) + sourcePort(uint16) + tags` |
| `OP_CALLBACKREQUESTED` | Server -> LowID Client | `targetIP(uint32) + targetPort(uint16)` |
| `OP_CALLBACKREQUESTED_IPV6` | Server -> v6-capable LowID Client | `targetIPv6(hash16) + targetPort(uint16)` |
| `OP_CALLBACKFAILED` | Server -> Client | Empty payload |

#### Multi-line server messages

`messageLogin` and `messageLowID` may span several lines. They travel as **one**
`OP_SERVERMESSAGE`, not one packet per line: servers from 16.40 on batch them and eMule has
split them client-side ever since (`srchybrid/ServerSocket.cpp:169-174`).

Any newline style works in the YAML — a literal block scalar, or a `\n` / `\r\n` escape in
any quoting style. `config.normalizeMessageText` folds them all to LF at load, and
`ed2k.BuildServerMessagePacket` emits **CRLF** on the wire.

CRLF is emitted even though both eMule trees accept a bare LF:

- **MFC** tokenises with `strMessages.Tokenize(_T("\r\n"), iPos)`. `CString::Tokenize` takes
  a *set of delimiter characters*, not a substring — the same idiom appears as
  `Tokenize(_T(" \t\r\n"))` with the comment *"tokenize by whitespace"*
  (`srchybrid/DirectDownloadDlg.cpp:87`). So CR and LF each end a line, and runs of them
  collapse.
- **Qt** folds CR into LF and splits with `Qt::SkipEmptyParts`
  (`src/core/server/ServerConnect.cpp:1114-1128`), whose comment records that splitting on
  the literal `"\r\n"` had missed bare-newline servers.

A third-party client that splits on the literal two-character sequence has no such
tolerance, and CRLF is the only encoding both strategies read identically. Pinned by
`ed2k/servermessage_test.go`.

Four consequences worth knowing when writing the text:

- **Blank lines vanish.** Both trees skip empty tokens, so an empty line is not a blank
  line in the client's info pane. Trailing newlines are trimmed at config load for the same
  reason — invisible to eMule, but a naive splitter would draw one.
- **Three line prefixes are reserved.** A line starting with `server version` sets the
  server's displayed version; `ERROR` and `WARNING` are diverted to the log with
  `bOutputMessage = false` and never shown as message text (`ServerSocket.cpp:176-201`).
  Matching is anchored at the start of each line, so mentioning the words mid-sentence is
  fine.
- **Keep it ASCII.** The text is decoded as UTF-8 only once the client knows the server's
  `SRV_TCPFLG_UNICODE` bit (`ServerSocket.cpp:159`), and that bit arrives in `OP_IDCHANGE`
  (`ServerSocket.cpp:291`) — which the handshake sends *after* both messages. On a first-ever
  connect the flag is still `0` and non-ASCII is read as ANSI.
- **A URL must end its line.** Both trees linkify a bare URL in the server-info pane, so a
  line ending in `https://emule-qt.org/` arrives clickable with no markup — that is how the
  shipped `messageLogin` advertises the client. The scheme table is shared
  (`srchybrid/OtherFunctions.cpp:89-100` and `src/gui/utils/TextLinks.h:47-52`: `ed2k://`,
  `http://`, `https://`, `ftp://`, `www.`, `ftp.`, `mailto:`, `magnet:?`), and both run the
  link from the scheme to the next whitespace. They diverge on what happens next: Qt chops a
  trailing `.,;:!?)` (`TextLinks.h:118-120`), the MFC tree does not, so `…/org/.` there
  resolves to an address with the period in it. Ending the line with the URL makes the two
  agree. Pinned by `config.TestShippedLoginMessageIsClientSafe`, with the rules themselves
  covered by `TestClientSafeLineRules`.

### UDP Payloads (Implemented Here)

`OP_GLOBSERVSTATRES` doubles as the reply to the obfuscation **crypt-ping** bootstrap (a raw
challenge on the obfuscated UDP port, `tcp.port + 12`). The reply carries the UDP obfuscation key at
offset +36; see [server-udp-crypt-ping.md](server-udp-crypt-ping.md).

| OP | Direction | Payload Format |
|---|---|---|
| `OP_GLOBFOUNDSOURCES` | Server -> Client | `fileHash(hash16) + sourceCount(uint8) + repeated(source entry)` |
| `OP_GLOBSEARCHRES` | Server -> Client | One file per UDP packet: `fileRecord = fileHash + sourceID + sourcePort + tags` |
| `OP_GLOBSERVSTATRES` | Server -> Client | `challenge(uint32) + users(uint32) + files(uint32) + maxConnections(uint32) + softLimit(uint32) + hardLimit(uint32) + udpFlags(uint32) + lowIDUsers(uint32) + udpPortObf(uint16) + tcpPortObf(uint16) + udpServerKey(uint32, per-client — derived from the client IP) + observedClientIPv4(uint32)` |

The trailing `observedClientIPv4` is the address the server saw the requester on — the same
4 bytes Lugdunum `eserver` already sends and eMule discards, logging only *"contains %d
additional bytes"* (`srchybrid/UDPSocket.cpp:384-388`). Purely additive: a stock client
ignores it, and one taught to read payload offset +40 gets IPv4 address reflection. Omitted
for an IPv6 requester, which has no 4-byte form — those learn their address from the
`CT_MOD_YOUR_IP` tag in `OP_SERVERIDENT` instead.

With `gossip.enabled`, `udpPortObf` advertises `udp.portGossip`, because a peer checks the
source port of our obfuscated frames against this value. That port defaults to
`tcp.port + 14` on a socket of its own, so a client of a gossiping server is told
`tcp.port + 14` and one of a gossip-less server `tcp.port + 12`; both sockets run the same
obfuscated handler, and `tcp.port + 12` stays bound for the bootstrap crypt-ping. The two
were one socket for a while, which a Lugdunum peer cannot work with — it decrypts a reply
from `tcp.port + 12` with the ping challenge instead of our ServerKey. See
`server-gossip.md` §1.
| `OP_SERVERDESCRES` (old) | Server -> Client | `name(string) + description(string)` |
| `OP_SERVERDESCRES` (extended) | Server -> Client | `challenge(uint32) + tags` |

### NAT Payloads (`PR_NAT`)

| Item | Format / Note |
|---|---|
| NAT envelope | `protocol(1) + size(4, little-endian) + opcode(1) + payload` |
| NAT endian note | Envelope `size` is little-endian; `peerIP/peerPort` and register ACK endpoint fields are big-endian |
| `OP_NAT_REGISTER` (client -> server) | `userHash(hash16)` or `userHash(hash16) + stats(3 * uint16)` |
| `OP_NAT_REGISTER` (server -> client) | `serverPort(uint16, BE) + serverIP(uint32, BE)` |
| `OP_NAT_SYNC2` | `srcHash(hash16) + connAck(uint32) + dstHash(hash16)` |
| `OP_NAT_SYNC` | `peerIP(uint32, BE) + peerPort(uint16, BE) + peerHash(hash16) + connAck(uint32)` |
| `OP_NAT_FAILED` | `reason(uint8) + targetHash(hash16)` (reasons: `0x01` not registered, `0x02` no common family, `0x03` rendezvous restricted) |
| `OP_NAT_KEEPALIVE` | Empty payload (`payloadLen=0`) |
| `OP_NAT_PING` | Empty payload (`payloadLen=0`) |
| legacy keepalive (non-`PR_NAT`) | Raw single-byte UDP packet (no NAT envelope/opcode) |

A matched keepalive of either form also counts as **eD2K session liveness**: the user hash
it identifies is looked up among logged-in connections and that socket's read deadline is
pushed out by `tcp.disconnectTimeout`. Without this, a share-only LowID client — one that
publishes files, keeps its `PR_NAT` registration fresh so it stays punchable, and sends no
TCP traffic for hours — was reaped by the idle path and all of its sources vanished, even
though the keepalives proved it reachable.

## Notes

- Exact field encoding for each payload is implemented in:
  - `ed2k/tcpoperations.go`
  - `ed2k/udpoperations.go`
  - `ed2k/packet.go`
  - `ed2k/nattraversal.go`
- `WARNING ` and `ERROR ` are reserved leading words in `OP_SERVERMESSAGE`. Both clients
  match on them and divert such a line to the warning or error log instead of the
  server-info pane (`srchybrid/ServerSocket.cpp:188-201`,
  `eMuleQt/src/core/server/ServerConnect.cpp:1208-1210`), so the prefix on the publish-limit
  and login-gate messages is routing, not decoration. Do not use either word to open an
  ordinary informational message.
- Server-to-server gossip *is* implemented — the UDP `SERVER_LIST_REQ/RES` (`0xa0`/`0xa1`)
  exchange and the peers it learns. See [`server-gossip.md`](server-gossip.md); an earlier
  version of this note said the opposite.
- For how this surface compares to other server implementations — in particular
  which extensions are ours alone and which LowID↔LowID design belongs to whom —
  see [`ed2k-server-rust-comparison.local.md`](ed2k-server-rust-comparison.local.md).
