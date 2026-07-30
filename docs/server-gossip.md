# Server-to-server gossip

How eNode-go exchanges peer servers with other eD2K servers, so `OP_SERVERLIST` is
populated from the live network instead of only from the static `servers:` list.

Everything below marked **measured** was verified against the original Lugdunum
`eserver` 17.14 binary running in Docker (`lugdunum-eserver/`), not inferred from
a reimplementation. Where the two disagreed, the binary won — three of our documented
assumptions turned out to be wrong, and those corrections are called out inline.

---

## 1. Port map

Lugdunum derives every port from its eD2K TCP port `P`. eNode-go now does the same,
with each port configurable.

| Port | eNode-go default | Lugdunum name | Role |
|---|---|---|---|
| `P` | 5555 | `port` | eD2K TCP — **and obfuscated TCP** |
| `P+4` | 5559 | `serv_to_serv_sock` | main eD2K UDP: client queries **and** plain server↔server |
| `P+8` | — | `port_4669` | wrong-port detection; not implemented here |
| `P+12` | 5567 | `obfpingport` | obfuscated **bootstrap ping** — and our **gossip** socket |
| `P+14` | — | `portUDPOBF` | eserver's own gossip listener; see the warning below |

Three things about this layout are easy to get wrong:

**`P+12` and `P+14` are both UDP.** The question is usually posed as "TCP+12/TCP+14";
it is not. Obfuscated *TCP* has no separate port at all — `portTCPOBF` defaults to
`port`, so it shares the plaintext listener and is detected from the first bytes on the
wire. Running the real binary, `print` reports `portTCPOBF=4661` against `port=4661`,
and eMule agrees: `srchybrid/UDPSocket.cpp:394` falls back to
`nTCPObfuscationPort = pServer->GetPort()`. eNode-go now enables obfuscation on the
plaintext listener for this reason, while keeping `tcp.portObfuscated` bound for clients
pinned to it.

**`P+12` is the *bootstrap* port**: eMule sends its very first obfuscated
`OP_GlobServStatReq` there before it has learned anything
(`srchybrid/ServerList.cpp:294`), and `GetServerByIPUDP` accepts a reply from `P+4`, the
advertised port, or `P+12` (`ServerList.cpp:568-570`).

**We gossip *from* `P+12`, and that is forced rather than chosen.** Two of eserver's rules
have to hold at the same time, and only one port satisfies both:

1. It skips a peer whose obfuscated frames do not arrive from the `portUDPOBF` that peer
   advertised — `continue because portUDPobf(%d) != sin_port(%d)`. So the port we send from
   must be the port we publish.
2. It recovers a peer's **TCP** port from the UDP source port of an obfuscated frame by
   **subtracting 12**. Measured on a shared Docker network: a frame from our 5567 was booked
   to 5555, one from 5569 to a nonexistent 5557, after which it logged `received a pong from
   unknown server 203.0.113.3:5557`, its ping bookkeeping never confirmed, and we stayed out
   of its records.

`P+14` — eserver's own `portUDPOBF` default — satisfies (1) and breaks (2), so it cannot be
used. `udp.portGossip` therefore defaults to `P+12` and **shares** the obfuscated client
socket rather than binding a second one. An explicit `udp.portGossip` still binds a separate
socket and advertises it, for a peer implementation known to want that; against a real
eserver it breaks the ping bookkeeping.

Note what this means about the reference implementation: eserver advertises `portUDPOBF =
P+14` while sending its own obfuscated frames from `P+12`, so *its* advertised value and
source port disagree — a peer enforcing rule (1) against it would skip it. We publish the
port we actually use.

A related invariant that has not changed: gossip must be sent through a *listener* socket,
never a freshly dialled one. An ephemeral source port either gets us ignored or gets
recorded as our server port; the latter is where the Rust implementation's "phantom clones
on port 36258" came from.

These are **defaults, not invariants** on the receiving side: `portTCPOBF`, `portUDPOBF` and
`portOtherServers` are all `donkey.ini` parameters. A peer that moved them is unreachable at
the default, so we always prefer the value it advertises at offset 32 of its extended
`0x97`, and fall back to `P+14` only when it has told us nothing.

---

## 2. The obfuscation envelope is eMule's, unchanged

"Lugdunum server-to-server obfuscation" is eMule's `CEncryptedDatagramSocket`
server-UDP obfuscation with a different key input. Nothing new had to be implemented:
`ed2k/udpcrypt.go` already produced this exact format for the client-facing listener.

```text
marker(1, never E3/D4/C5) │ salt(2 LE) │ RC4( magic(4 LE) │ padlen(1, low nibble) │ padding │ inner E3-frame )
RC4 key = MD5( key(4 LE) ‖ direction(1) ‖ salt(2 LE) )      -- no 1024-byte keystream drop
magic   = MAGICVALUE_UDP_SYNC_SERVER = 0x13EF24D5           -- both directions
```

The direction byte is the only thing that distinguishes who is speaking:
`MAGICVALUE_UDP_SERVERCLIENT 0xA5` and `MAGICVALUE_UDP_CLIENTSERVER 0x6B`
(`srchybrid/EncryptedDatagramSocket.cpp:143-144`). Since this server is a *client* when
it addresses a peer and a *server* when it answers one, `UDPCrypt` needs all four
combinations, which is why `EncryptAsClient` and `DecryptFromServer` exist alongside
`Encrypt` and `Decrypt`.

### Which key, which direction — measured

Every pairing below was determined by brute-forcing the plausible candidates against
eserver 17.14, because getting it wrong fails *silently*: the far end sees junk that
misses its magic check and drops it.

| Frame | Key | Direction | How we know |
|---|---|---|---|
| we → peer (phases 3, 4) | the peer's `ServerKey` | `0x6B` | eserver accepts and replies |
| peer → us (reply to 3, 4) | **the peer's own `ServerKey`** | `0xA5` | **measured**: of `{peerServerKey, ourDerivedKey, pingChallenge, ourSecret} × {0x6B, 0xA5}`, only `(peerServerKey, 0xA5)` yielded a valid magic |
| peer → us (reply to phase 2) | the challenge we sent | `0xA5` | no `ServerKey` exists yet (`UDPSocket.cpp:159-171`) |
| client/peer → us (initiating) | the `ServerKey` **we** published | `0x6B` | the existing client-facing path |

The second row is the non-obvious one: the key belongs to the *relationship as the peer
defines it*, and the direction byte alone says who is talking. Our own derived key failed
in both directions. Without those two extra decrypt attempts (`decryptPeerReply`) both
peer replies fell through to the crypt-ping heuristic and were dropped, so no peer ever
got past phase 2.

### `ServerKey` — who derives what

Each server holds a private secret (`udp.serverKey` here, `seckey` in `donkey.ini`) and
computes, per peer, a `ServerKey` from that secret plus the peer's IP. It publishes the
result at offset **+36** of its extended `0x97`. The peer encrypts with it; the issuer
recomputes it from the source IP on receipt. No key exchange, no per-peer state.

The derivation is therefore **entirely private to each server** — a peer only ever echoes
back the value you published. Our `deriveUDPKey` (`ed2k/udpcrypt.go`) truncates MD5 to
its first LE word where Lugdunum's `IPObfuscate` XOR-folds all four; that difference is
invisible on the wire and needs no reconciliation.

---

## 3. The four phases

One round per peer every `gossip.intervalSeconds` (default 150 s, just inside
Lugdunum's ~165 s keepalive so our entry never lapses between rounds).

Every frame is a **fire-and-forget write** through a listener socket. Nothing waits for
a reply: the inbound handlers advance the peer's state as answers arrive, and the next
round acts on whatever state it reached. That makes the loop a plain scheduler — no
per-peer goroutine, no timeouts, no pending-request bookkeeping.

### Phase 1 — plain bootstrap · our `P+4` → peer `P+4`

```text
E3 A0 │ our_ip(4) │ our_tcp_port(2 LE) │ challenge(4 LE)     register + implicit list request
E3 96 │ challenge(4 LE)                                       status probe
```

The `0x96` challenge follows eMule's convention, `0x55AA0000 + GetRandomUInt16()`
(`srchybrid/ServerList.cpp:306`).

> ❗ **Correction — the `0x55AA` marker does not select the extended reply.** This was
> previously recorded as fact, taken from the Rust server's `is_server_probe` heuristic
> and an eMuleQt comment. **Measured**: a plain `0x96` carrying challenge `0x55AA1234`
> on `P+4` gets back a 34-byte datagram — 32 bytes of payload ending at the UDP flags,
> with no obfuscation ports and no `ServerKey`. The same server answers the *obfuscated*
> ping on `P+12` with a 46-byte datagram that does carry them.
>
> **Lugdunum keys the extended reply off the channel, not off the challenge.** Anything
> needing a `ServerKey` must go through `P+12`, which is exactly why eMule tries the
> obfuscated ping first and only falls back to the plain one
> (`ServerList.cpp:272-296`) — and why phase 1 alone can never key a peer.
>
> We answer the full extended form on both channels, which is strictly more generous
> than Lugdunum and breaks no client.

`0xA0`'s payload is documented as `<IP 4><PORT 2>` (`srchybrid/Opcodes.h:201`), six
bytes; Lugdunum's server-to-server form appends a 4-byte challenge. We send the 10-byte
form (the extra bytes are additive trailing data) and accept either on receipt.

### Phase 2 — obfuscated bootstrap ping · our `P+14` → peer `P+12`

```text
→  challenge(4 LE) │ 0..14 random pad bytes        RAW, UNENCRYPTED, first byte forced ∉ {E3,D4,C5}
←  obfuscated, keyed on OUR challenge, direction 0xA5:
   E3 97 │ … │ portUDPOBF(2) │ portTCPOBF(2) │ ServerKey(4) │ observed_ip(4)
```

Unencrypted is the protocol, not an oversight: we hold no key for this peer yet, and
obtaining one is the point. eMule is explicit — *"we don't encrypt raw packets (!)"*,
`srchybrid/UDPSocket.cpp:762`. The first byte is forced away from the protocol constants
because the receiver dispatches on byte 0; a challenge that happened to begin `0xE3`
would be read as a plaintext frame, which happens to roughly 1 in 85 pings.

Sent to `P+12` rather than the advertised port because `P+12` is the bootstrap port by
definition — the one offset a peer cannot have moved without becoming unreachable to
stock clients too.

Re-sent every round even for an already-keyed peer: a peer rotates its `ServerKey` when
our observed address changes (`srchybrid/Server.cpp:279-291`), so re-pinging keeps it
fresh.

### Phase 3 — obfuscated gossip · our `P+12` → peer's advertised `portUDPOBF`

Every frame wrapped with the peer's `ServerKey`, direction `0x6B`:

```text
E3 A0 │ our_ip │ our_tcp_port │ challenge      re-register, obfuscated ⇒ counts as verified
E3 A4                                           SERVER_LIST_REQ2: "send me your list"
E3 A7                                           SERVER_LIST_REQ_IPV6 (ours), only if the peer advertised FlagIPv6
```

**No `0x97` is sent here, and its absence is deliberate.** An earlier version volunteered
one whenever a peer had registered with us, echoing the challenge from that `0xA0`. A peer
keeps a *separate* per-peer ping challenge, so eserver rejected every one — `server %s:%d
sent a bad challenge %x instead of %x` — and, worse, the rejection reset its ping
bookkeeping for us. A `0x97` is only ever correct as a *direct reply*, because only the
reply knows which challenge was asked; the inbound handler already sends those with the
right value. Measured; see [`interop-docker-tests.md`](interop-docker-tests.md) §4.

### Phase 4 — name:desc admission test · our `P+12`, obfuscated

```text
E3 A2 │ challenge(4 LE)      OP_SERVERDESCREQ
←  E3 A3 │ challenge │ tags   or the old <name string><desc string> form
```

**This phase was missing from our earlier reconstruction of the protocol entirely.** The
binary's own strings show it is eserver's actual admission test: `servdescreply()`,
`received a bad name:desc reply from server %s:%d (bad name)/(bad desc)`, and then
`Adding server %s:%d name=%s desc=%s` / `Updating server %s:%d …`. A peer that answers
everything else but has no usable name is not admitted.

We accept either reply form. The name must be non-empty, ≤255 bytes and free of control
characters; the description may be empty but is bounded at 512. Those strings reach logs,
the peer table and other servers' lists, so an unbounded or control-laden value from an
unauthenticated source is not storable.

**eserver reads one more field here than the name and description, and it is decisive.**
The `ST_VERSION` (`0x91`) tag — string, or uint32 with major in the high half and minor in
the low half — is parsed as `%d.%d`, and a peer is admitted to its `working` set only if
`major > 17`, or `major == 17` and minor is at least 7. That set is what its `server.met`
and *both* of its peer-list replies are drawn from, so a peer below the bar is held in
memory, named in `vs`, pinged forever — and never mentioned to anyone. There is no
rejection log for it, on either side.

We therefore send `ed2k.GossipVersionStr` — `"17.14 (eNode-go v0.1.0)"` — as a **string**
tag. Both tag forms end at the same `sscanf`, which stops at the space and ignores
everything after the minor, so the compatibility claim and our real identity fit in one
value. That matters because this reply is not gossip-only: the same handler answers a
client's `0xA2`, and eMule shows the tag verbatim in its server-list Version column. The
`17.14` prefix is a claim about protocol compatibility with a 2007 binary and never moves;
the rest is derived from `ENodeVersionStr` so a release carries it. See §8 and
`interop-docker-tests.md` §5.

---

## 4. Opcodes

| Opcode | Hex | Payload |
|---|---:|---|
| `OP_SERVER_LIST_REQ` | `0xA0` | `<ip 4><port 2 LE>` + optional `<challenge 4 LE>` |
| `OP_SERVER_LIST_RES` | `0xA1` | `<count 1>` then count × (`<ip 4><port 2 LE>`) |
| `OP_SERVER_LIST_REQ2` | `0xA4` | empty |
| `OP_SERVER_LIST_REQ_IPV6` | `0xA7` | empty — **eNode-go extension** |
| `OP_SERVER_LIST_RES_IPV6` | `0xA8` | `<count 1>` then count × (`<ipv6 16><port 2 LE>`) — **eNode-go extension** |

IPv6 gets its own opcode pair rather than a trailing block on `0xA1`, so `0xA1` stays
byte-identical to what a real eserver produces and consumes. `0xA7`/`0xA8` are free in
the *server↔client* namespace: `srchybrid/Opcodes.h` ends that block at
`OP_SERVER_LIST_REQ2 0xA4`, and the `OP_FWCHECKUDPREQ 0xA7` / `OP_KAD_FWTCPCHECK_ACK
0xA8` at `:283-284` are in the separate client↔client block. That is the same reasoning
that allocated `OpGlobGetSourcesIPv6 0xa5`/`0xa6`. They are sent only to a peer that
advertised `FlagIPv6`, so a stock eserver never sees them.

**On IP byte order**, which reads ambiguously in every description of this protocol: the
reference calls these addresses "network order" while our `OP_SERVERLIST` builder writes
a little-endian uint32 — and those are the same four bytes. For `1.2.3.4`, network order
is `01 02 03 04`, and `IPv4ToUint32LE` gives `0x04030201`, which serialises
little-endian to `01 02 03 04`. There is nothing to choose between.

---

## 5. Admission and merge policy

### State machine

```text
seen ──phase 2 reply──▶ keyed ──phase 4 reply──▶ described ──list exchange──▶ verified
                                                 └── advertisable from here ──┘
```

- **seen** — an address, nothing proved. Reached by a plaintext `0xA0`, or by an entry
  harvested from someone else's list.
- **keyed** — the bootstrap ping came back; we hold the peer's `ServerKey`.
- **described** — it answered `0xA2`, obfuscated, with a usable name and description.
- **verified** — it also answered a list request. Better evidence, but not required.

**The admission bar is `described`, not `verified`, and that is a correction from live
interop.** Requiring a list reply looked right on paper but is unsatisfiable: a peer with
an empty peer table — the first two servers in any new mesh, or a lone eserver — has no
`0xA1` to send, so it would stay unadvertisable forever and a mesh could never bootstrap.
Confirmed against eserver 17.14: it answers our obfuscated `0xA2` with its identity and
sends no list at all, and its own admission test is exactly that reply.

The security property is unaffected. Reaching `described` already required the peer to
answer a frame we encrypted with the `ServerKey` **it** issued for our address — the one
thing a client masquerading as a server cannot do. A list reply only adds evidence that
the peer has peers, which says nothing about whether it is a server.

### Why obfuscation is the gate, not an optimisation

Two independent reasons, both confirmed by the binary:

- **Trust.** Anyone can spray plaintext `0xA0` at a server. Completing the obfuscated
  round-trip requires holding a `ServerKey` the peer derived for *your* IP and handed to
  you. eserver drops the plaintext forms outright — two distinct log strings,
  `ignore non obfuscated OP_SERVER_LIST_REQ from %s` and
  `ignore non obfuscated OP_SERVER_LIST_RES from %s`.
- **Propagation.** Until the round-trip completes the peer will not include you in the
  `0xA1` it serves to others.

We mirror both. A plaintext `0xA0` is recorded as a hint worth probing but can never
promote a peer, and a plaintext list request is refused — serving our peer table to an
unauthenticated sender hands a scanner the whole mesh for one datagram.

Note that "obfuscated" is decided from the *raw first byte*, not from which listener
received the frame. `UDPCrypt.Decrypt` deliberately passes a plaintext `PR_ED2K` frame
straight through (so a plaintext login on the obfuscated port still works), so without
that check a plaintext `0xA0` aimed at the gossip port would be indistinguishable from an
authenticated one — and for gossip that distinction *is* the authentication.

### What is rejected from a peer's list

An entry is refused if it:

- fails eMule's `IsGoodServerEntry` — port 0, `0.*`, multicast/reserved/broadcast
  (`>= 224.0.0.0`) unconditionally, plus loopback and RFC1918/link-local unless
  `gossip.allowPrivatePeers`. A dynIP peer is exempt from the IP test, as
  `CServerList::IsGoodServerIP` does (`srchybrid/ServerList.cpp:322-325`);
- **is us** — the advertised address or any local bind address. Peers echo back whatever
  they observed, which on a multi-homed or NATed host is not the advertised IP, and
  re-ingesting it recreates phantom self-entries;
- is, or was within 30 minutes, a connected client. A client is not a server; this
  catches an mldonkey that registered with real seeds, disconnected from us, and comes
  back inside someone's `0xA1`;
- is blocked by the access filter (see `access-filters.md`);
- arrives from a sender we have not at least keyed — eserver's
  `received a servlist from unknown server %s:%d`. `peerSeen` is not enough, since anyone
  can reach `peerSeen` just by appearing in someone else's list;
- would exceed `gossip.maxServers` (default 4096, eserver's own `maxservers`). A cap is a
  DoS guard, not a tuning knob.

`0xA1` is also **overloaded** — mldonkey *clients* emit it with an unrelated payload — so
a frame whose declared count does not match the bytes present is rejected outright rather
than partially accepted. Parsing whatever happens to fit is exactly how a foreign payload
becomes a list of garbage `ip:port` pairs that then propagate.

A peer that produces no inbound frame for `gossip.maxFailures` consecutive rounds is
**parked**: no longer contacted, but retained, so any inbound frame revives it. A server
down for an afternoon should not have to be rediscovered.

### Deduplication

Peers are identified by **(canonical address, TCP port)**, which is
`CServerList::AddServer`'s rule: the address string, compared case-insensitively,
with the port qualifying it, so two ports on one host stay two entries
(`srchybrid/ServerList.cpp:202-240`). On a duplicate the entry already held wins and
the incoming one is discarded.

Three places apply it, because peers arrive by three routes:

- the gossip table keys `g.peers` by address, so a peer harvested twice is one entry;
- `Engine.AddServer` deduplicates the configured list on `storage.ServerAddrKey`, so
  a peer listed twice under `servers:` is seeded once and logs a warning naming it;
- `advertisableServers` collapses what is left across both sources when it builds
  `OP_SERVERLIST`.

The canonicalization matters for IPv6: an operator who writes `2001:DB8::1` in the
config and a peer that reports `2001:db8::1` are the same server, and comparing the
raw strings would advertise it twice.

---

## 6. Persistence — `server.met`

Verified peers are written to `gossip.serverMetFile` (default `data/server.met`) every
`gossip.persistIntervalSeconds` (225 s, eserver's `autoservlist` cadence) and reloaded at
boot. The configured seeds are the fallback for when that file is absent or empty —
eserver documents `seedIP`/`seedPort` as "used if no serverList.met file is present (or
if it's empty)" for the same reason: once a mesh is known, the operator's original
bootstrap list is stale information.

The format is the real eMule one (`srchybrid/ServerList.cpp:142-160` reader, `:597-640`
writer), so an operator can point an eMule at the file to see what the server learned,
and eserver's own output can be fed back in as seeds:

```text
uint8   version      0xE0 (0x0E also accepted on read)
uint32  count
count × { uint32 ip │ uint16 port │ uint32 tagcount │ tagcount × tag }
```

Tags are the old 1-byte-name form, which `Buffer.PutTags`/`GetTags` already emit and
consume, so no separate `.met` tag codec was needed. Only `ST_SERVERNAME` and
`ST_DESCRIPTION` are stored: ports, `ServerKey`s and counts are all re-learned within one
round, so writing them would only create a way for the file to disagree with reality.

Two details that matter:

- The file is written to a temporary name and **renamed into place**. The table is
  rewritten wholesale on a timer, so a crash mid-write would otherwise leave a truncated
  peer list — losing the mesh the file exists to preserve.
- An empty verified set is **not** written. Truncating a good file to zero entries because
  this boot has not finished its first handshake would throw the mesh away.
- The shutdown write **blocks**. A clean stop flushes once more so it does not lose up to a
  full interval of learned peers, and the stopper waits for that write to finish rather
  than only signalling it — otherwise `main`'s remaining defers run and the process exits
  mid-write. A file this small usually won that race, which is why the bug went unnoticed:
  when it lost, the flush vanished and a `server.met.tmp-*` was left behind. Same shape as
  the snapshot stopper in [`docs/storage-snapshot.md`](storage-snapshot.md).

An entry whose IP field is 0 is skipped on read: eMule writes 0 for a dynIP server
deliberately, and we have no hostname field to resolve it from — but its tags are still
consumed so the following entries stay aligned.

---

## 7. Configuration

```yaml
udp:
  # The port obfuscated gossip is sent from, and the portUDPOBF advertised to peers.
  # Defaults to portObfuscated (tcp.port + 12), which is then shared rather than bound
  # twice. tcp+12 is required, not preferred — see section 1.
  portGossip: 5567

gossip:
  enabled: true
  seeds: []                 # falls back to the top-level `servers:` list
  intervalSeconds: 150      # inside Lugdunum's ~165 s keepalive
  maxServers: 4096          # eserver's maxservers
  maxFailures: 5            # consecutive failed rounds before parking
  publishIPv6: true         # emit/consume 0xA7 / 0xA8
  allowPrivatePeers: false  # eMule's FilterLANIPs, inverted — see below
  persist: true
  serverMetFile: "data/server.met"
  persistIntervalSeconds: 225
```

`allowPrivatePeers` admits loopback and RFC1918 peers. It stands in for both of eMule's
escape hatches — `FilterLANIPs()` being off, which exists "so a private-network server can
be added for LAN test setups" (`src/core/server/ServerList.cpp:1070-1073`), and
`GetAllowLocalHostIP()`, which re-admits `127.*`. It is required to gossip with a server
on the same host, including the reference container, and off by default.

Files the server writes live under `data/` (gitignored); config and operator-supplied
inputs stay in the repo root. Paths resolve via `tests.FixRelativeTestingPath`, so a
relative path means the same thing whether the binary was started from the repo root or a
test is running from a package subdirectory.

---

## 8. Interop status against eserver 17.14

Automated, and run against the real binary rather than a reimplementation:

```sh
ENODE_INTEGRATION=1 go test ./tests/interop/ -v -timeout 30m
```

Both servers run as containers on one Docker network, so **both directions are routable**.
That is what makes the eserver→us half testable at all — see
[`interop-docker-tests.md`](interop-docker-tests.md) for the rig, and note that everything
below now has a test behind it instead of a manual run.

**Us → eserver, verified:**

| Step | Evidence |
|---|---|
| Phase 1 accepted | eserver answers the plain `0x96` with the 34-byte short form |
| Phase 2 keyed the peer | `cinfo from …:4661 ServerKey=0x… UDPobf=4675 TCPobf=4661 flags=0x000007fb` — matching what `probe.py` measured independently |
| Phase 3 accepted | eserver replies to our obfuscated frames on its advertised `portUDPOBF` (4675) |
| Phase 4 admitted the peer | its real identity read off the wire: `name="lugdunum-ref" desc="Lugdunum eserver 17.14 reference (interop test)"` |
| Peer advertised + persisted | `data/server.met` written in eMule format with that name and description; the peer reaches clients through `OP_SERVERLIST` |

**eserver → us, now verified.** It probes us back, we answer, and it enters us in its live
table. Its own `vs` output is the evidence:

```text
[  1]  203.0.113.3:5555 {U5567}{T5565}{Kc588ddd9}  2000[1000]/1000  0  7/0 …  enode
```

`{K…}` appears only once it holds a ServerKey for us, so phase 2 completed; `{U}`/`{T}` are
the ports from our `0x97`; the trailing name came from the tags in our `0xa3`, so its
name:desc admission test was answered. None of its six refusal strings appear.

Getting here cost two real defects, both invisible to unit tests and both described in
[`interop-docker-tests.md`](interop-docker-tests.md) §4: the obfuscated source port had to
move from `P+14` to `P+12`, and the unsolicited `0x97` echo had to go. The second was
masked by the first.

**eserver marks us `working`, and getting there took a third defect.** It used to hold us
in memory while refusing to write us to its `server.met` or name us to other servers — both
gated on an internal flag whose only writer requires the `ST_VERSION` tag in our `0xA3`
reply to parse as `>= 17.7`, where we advertised `0.3`. The same flag gates its peer-list
builder, shared by `OP_SERVERLIST` and `OP_SERVER_LIST_RES`, so a non-`working` peer is
never named to anyone — which is why `TestGossipPropagatesThroughEserver` saw no reply at
all rather than an empty one, and was a skip.

Sending `GossipVersionStr` (§3) fixed all three at once. Both interop cases now assert
eserver's `server.met` instead of reporting it, and the propagation case is live. §5 of the
interop doc has the detail; the address-level derivation is in
`eserver-working-flag-disassembly.local.md`.

### Client-facing regression

`python3 lugdunum-eserver/run/probe.py 127.0.0.1 5555` against eNode-go confirms the
extended `0x97` still decodes on both channels, with the 4 trailing observed-IP bytes.
`portUDPOBF` now reports 5567 whether gossip is on or off, since the gossip socket is the
obfuscated client socket.
