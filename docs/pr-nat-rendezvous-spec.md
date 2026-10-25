# `PR_NAT` rendezvous: specification for servers and clients

Written 2026-10-25. This is the contract for implementing eNode-go's `PR_NAT` (`0xF1`)
LowID↔LowID rendezvous in another server or client. The reference implementation is
`ed2k/nattraversal.go`; the IPv6 parts are also described in
`ipv6-client-implementation-spec.md` §9, which this document supersedes as the wire
reference. It also defines the TCP wake-up, which spares clients logged in to the rendezvous
server any standing traffic, compares `PR_NAT` with the two other server-coordinated schemes
on the network, Lugdunum's NAT callback and ed2k-server's hole punch, and works out what each
costs on the wire.

## What it does

Two clients that cannot accept connections (two IPv4 LowIDs, or two hosts behind stateful
IPv6 firewalls) each keep a UDP mapping open towards a rendezvous server. When one asks for
the other by user hash, the server sends **both** of them the other's public UDP endpoint as
it observed it, in one step. Both then punch towards each other. The server takes no part in
what follows; the data path between the peers (a stream over UDP, or a TCP connection over a
punched IPv6 path) is up to the clients.

The registry is keyed by user hash, not by eD2K login. Two clients logged in to different
servers, or to none, can meet through any server that offers `PR_NAT`.

## Discovery

| Signal | Where | Meaning |
| --- | --- | --- |
| `0x40000` (`SRV_TCPFLG_NAT_RENDEZVOUS`) | TCP flags (`OP_IDCHANGE`), UDP flags (`OP_GLOBSERVSTATRES`) | the server runs `PR_NAT` and pairs any two registered hashes |
| `0x200000` (`SRV_TCPFLG_NAT_WAKE`) | TCP flags, UDP flags | the server wakes a logged-in target over TCP ([Waking a local target](#waking-a-local-target)) |
| `ST_NAT_PORT` (`0x9D`, uint16) | `OP_SERVERIDENT` tag | the rendezvous UDP port; default `2004` when absent |
| `0x200000` (`SRVCAP_NAT_WAKE`) | client login `CT_SERVER_FLAGS` | wake me; I keep no standing registration |

eNode-go sends `0x40000` when `natTraversal.enabled` and `natTraversal.serverIndependent`
are on, and `0x200000` when `natTraversal.enabled` and `natTraversal.tcpWake` are on (also
with `serverIndependent` off, because the wake pairs clients logged in to it). It sends
`ST_NAT_PORT` whenever it sends either flag. With both flags off it still runs the service
for pairs logged in to it, but advertises nothing, so clients that wait for a flag do not
use it.

`0x40000` was `0x8000` before 2026-10-20 (ed2k-server took `0x8000` for `OP_IPV6_UPDATE`).
A server implementing `PR_NAT` must use `0x40000`. The `OP_IDCHANGE` bit table in the
ed2k-server README lists every bit in use. `0x200000` is the wake-up's, so new bits go
above it.

A client is a participant once it registers. The only login bit is the wake-up's.

## Transport

- **Ports.** Send the first `REGISTER` (or a `SYNC2`) to `ST_NAT_PORT` (default `2004`), then
  follow the port in the register ack ([Field notes](#field-notes)). eNode-go accepts
  `PR_NAT` on `ST_NAT_PORT`, its main UDP port (`udp.port`, default 5559), its obfuscated
  UDP port and its gossip port; the ack on `ST_NAT_PORT` names the main UDP port. Send from
  the client's own UDP socket, the one peers will punch, so the observed source is the
  endpoint that matters.
- **IPv6.** eNode-go serves IPv6 `PR_NAT` only with `ipv6.enabled` and `natTraversal.ipv6`
  on. Without them IPv6 datagrams are dropped unanswered.
- **Plaintext.** `PR_NAT` is never obfuscated, on any port. A server takes it on the raw
  bytes, before any eD2K deobfuscation, and answers in plaintext, also on its obfuscated UDP
  port. A datagram that only decrypts to `0xF1` is not `PR_NAT` and is dropped.
- **Framing.** `[0xF1][size 4 LE = payload + 1][opcode 1][payload]`, the eD2K envelope with
  its own protocol byte. Opcodes are read only after `0xF1`, so they do not collide with
  `PR_ED2K` or `PR_EMULE` opcodes.
- **Byte order.** The envelope's size is little-endian, as in eD2K. **Every endpoint field
  inside a `PR_NAT` payload is big-endian, IP and port alike.** This differs from the rest of
  eD2K and is the easiest thing to get wrong.
- **Legacy keepalive.** A bare 1-byte datagram (any value) is accepted as a keepalive.

## Opcodes

| Opcode | Value | Direction | Payload | Size |
| --- | --- | --- | --- | --- |
| `OP_NAT_REGISTER` | `0xE4` | c→s | `hash 16` (longer payloads are accepted and the rest ignored) | 16 |
| `OP_NAT_REGISTER_EX` | `0xE3` | c→s | `hash 16, version 1` | 17 |
| `OP_NAT_REGISTER` (ack, IPv4) | `0xE4` | s→c | `port 2 BE, ipv4 4 BE` | 6 |
| `OP_NAT_REGISTER_IPV6` (ack) | `0xEC` | s→c | `port 2 BE, ipv6 16` | 18 |
| `OP_NAT_KEEPALIVE` | `0xE6` | c→s | empty | 0 |
| `OP_NAT_PING` | `0xE2` | s→c | empty: keepalive ack | 0 |
| `OP_NAT_SYNC2` | `0xE9` | c→s | `srcHash 16, connAck 4, dstHash 16` | 36 |
| `OP_NAT_SYNC` | `0xE1` | s→c | `peerIPv4 4 BE, peerPort 2 BE, peerHash 16, connAck 4` | 26 |
| `OP_NAT_SYNC_EX` | `0xE7` | s→c | `SYNC`, then `peerVersion 1` | 27 |
| `OP_NAT_SYNC_IPV6` | `0xED` | s→c | `peerIPv6 16, peerPort 2 BE, peerHash 16, connAck 4, peerVersion 1` | 39 |
| `OP_NAT_FAILED` | `0xE5` | s→c | `reason 1, targetHash 16` | 17 |

`0xE8`, `0xEA`, `0xEB` and `0xEF` (REPING, DATA, ACK, RST) are reserved and unused.

One message travels over the eD2K TCP session instead, in `PR_ED2K` (`0xE3`):

| Opcode | Value | Direction | Payload | Size |
| --- | --- | --- | --- | --- |
| `OP_NAT_WAKE` | `0x46` | s→c, TCP | `families 1`: `0x01` register over IPv4, `0x02` over IPv6 | 1 (7 B packet) |

`0x46` is unused by eMule, aMule, eMuleQt, Lugdunum and ed2k-server, and eMule and eMuleQt log
an unknown server opcode and carry on. A server sends it only to a session that set the
login bit.

### Field notes

- **Register ack.** The address is the **server's own** public address for that family, and
  the port is the one the server prefers for further `PR_NAT` traffic. An all-zero address
  means the server has none to announce: keep using the address you sent to. The IPv4 ack
  and the request share opcode `0xE4`; tell them apart by direction (and its 6-byte length).
- **`connAck`.** A 32-bit value the requester picks per attempt. The server copies it into
  both `SYNC`s, so each peer can tie the punch it receives to the attempt. eMuleQt uses a
  random odd value. It ties a `SYNC` to its attempt by the peer hash, and the punched path
  to the peer by source IP plus the user hash in its handoff, so it does not need `connAck`
  on the path itself.
- **`version`.** An opaque client byte for the peer's capabilities. A client that registered
  with `REGISTER_EX` and version > 0 gets `SYNC_EX` with the peer's version. Other IPv4
  receivers get the plain 26-byte `SYNC`. `SYNC_IPV6` always carries it, 0 when unknown.
- **`FAILED` reasons.** `0x01`: the target hash is not registered (no live candidate), or a
  wake-up for it timed out, also one that started because the peers shared no family.
  `0x02`: the two peers share no address family and no wake-up is possible. `0x03`: the
  server pairs only clients logged in to it (`serverIndependent` off), and one of the two
  is not. A target with no live candidate gets `0x01`, not `0x03`, because that check comes
  first.

## Server behaviour

**Registry.** Per user hash, at most one IPv4 and one IPv6 candidate. Each is the source
endpoint the server observed, never an address the client wrote into a payload. Each has its
own `lastSeen`. A candidate expires `registrationTTLSeconds` after it was last seen (default
90 s; 30 s before 2026-10-25). From then on it is not paired, a keepalive on it is unmatched,
and it no longer holds its hash's IP. A sweep runs every TTL/2, clamped to 5–60 s, and only
frees the memory. Each candidate also remembers which of the server's `PR_NAT` sockets its
last REGISTER, keepalive or auto-registering SYNC2 arrived on. An index from
endpoint to hash finds the entry of a keepalive, which carries no hash, in one lookup. An
endpoint is one socket, so it belongs to one hash: a REGISTER from an endpoint another hash
holds takes it over.

**REGISTER.** The candidate for the datagram's family is stored or refreshed, and the server
answers with the ack for that family. Because a user hash is public, the server checks the
sender first:

- **The hash is logged in to this server:** the REGISTER must come from that session's IPv4,
  or for IPv6 from the same /64 as the session's address. A session connected over IPv4
  also counts the IPv6 it announced in `CT_MOD_IP_V6`; a session connected over IPv6 has
  no IPv4. If the session has no address in that family, the next rule applies, so an
  IPv6 session may register IPv4.
- **Otherwise:** a live candidate is never replaced from a different IP. The same IP may
  change port, as after a NAT rebinding.

A refused REGISTER gets no answer.

**KEEPALIVE.** It carries no hash. The server looks up its source IP **and** port in the
index. On a match it refreshes that candidate and answers `OP_NAT_PING`. It
also counts as activity for the client's eD2K session on this server, so a share-only LowID
that sends nothing over TCP for hours is not reaped. An unmatched keepalive gets no answer.

**SYNC2.**

1. If the requester has no candidate in the datagram's family, the SYNC2 registers it,
   subject to the REGISTER checks. A requester therefore needs no standing registration.
2. If the target hash has no live candidate, the server tries to wake it (below). If it
   cannot, the answer is `FAILED 0x01` to the requester.
3. With `serverIndependent` off, both hashes of a registered target must be logged in to
   this server, else `FAILED 0x03`.
4. The server picks a family both peers have, **preferring IPv6**. If there is none, it
   tries to wake the target for the requester's families, else `FAILED 0x02`.
5. It sends the requester a `SYNC` with the target's endpoint and hash, and the target one
   with the requester's. Both carry the requester's `connAck`. The requester's `SYNC` leaves
   from the socket its SYNC2 arrived on. The forward to the target leaves from the socket the
   target's candidate last arrived on (the requester's socket when that is unknown), and
   over IPv6 from the address the server announced in its ack, so it matches the mapping the
   target opened. Two peers can therefore use different server ports, as when one follows
   the ack's port and the other does not.

Without a wake the server keeps no per-attempt state, and a repeated SYNC2 is answered again.

## Client behaviour

**To be reachable (target role).** On a server that wakes you (flag `0x200000`, and your
login carried bit `0x200000`), keep nothing: answer `OP_NAT_WAKE` as in
[Waking a local target](#waking-a-local-target). Anywhere else, while firewalled, register
on every family you can offer and keep each candidate alive:

1. Send `REGISTER` (or `REGISTER_EX`) from your UDP socket, every 5 s until acked. A
   refused one gets no answer, so back off: eMuleQt slows to one a minute after 6
   unanswered. On the ack, move this family's later `PR_NAT` traffic to the ack's address
   and port (the parts that are non-zero), and accept frames from there too.
2. Then send `KEEPALIVE` well inside the TTL. eMuleQt sends one every 60 s for a 90 s TTL.
   The keepalive keeps both the server's candidate and your NAT's mapping open. The `SYNC`
   that wakes you is unsolicited from your NAT's point of view, and it only gets in through
   that mapping. [RFC 4787](https://www.rfc-editor.org/rfc/rfc4787) (REQ-5) asks NATs to
   keep an idle UDP mapping for at least 2 minutes and recommends 5, so 60 s is inside it;
   some home routers drop mappings after 30–60 s anyway. Behind those a foreign target can
   miss a `SYNC`; a shorter interval trades traffic for reach (see "The other two, for
   comparison").
3. If keepalives stop being answered with `PING`, register again. The server lost the
   registration, or your NAT gave you a new port and a keepalive from it matches nothing.
   eMuleQt registers again after 65 s without a `PING`, that is after one unanswered
   keepalive, and does so at the default endpoint (server address, `ST_NAT_PORT`), since
   the learned one may be what broke. On eNode-go v0.5.1 and older, whose TTL is 30 s, each keepalive finds the
   candidate expired and the client registers again, so it is unregistered for about half
   of each minute there.

**To reach a peer (requester role).** Send `SYNC2` with your hash, a fresh `connAck` and the
peer's hash. Repeat a few times if no `SYNC` comes (eMuleQt: every 5 s, at most 3 times). On
`SYNC`, punch towards the endpoint and treat a datagram from it carrying the same `connAck`
as the peer, or match it by an equivalent check. On `FAILED`, try another path. On a wake
server, send a `REGISTER` over your other family right before the `SYNC2`, so the server can
pair on whichever the target has. eMuleQt sends the `SYNC2` over IPv6 when it can, and a
`REGISTER` over IPv4 right before it.

**Which peer.** Both sides need the other's user hash and a rendezvous server they both
registered with. For two clients on the same server, that server is the rendezvous, and the
hash comes from the source list or the hello.

## Cross-server use

A client logged in to another server can use an eNode-go server as its rendezvous. It needs
the same standing registration as a local client, for the same reason. The server has no
other way to reach it: it has no TCP session with the client to wake it, and the `SYNC`
forward reaches the client only through the UDP mapping that the keepalives hold open. Only
the target role needs this. A requester's `SYNC2` registers it on the spot.

Both peers must use the **same** rendezvous server. eNode-go servers do not share their
registries. Nothing in eD2K tells a requester which server a foreign target registered with.
A target would have to publish the pair (user hash, rendezvous `ip:port`) through Kad or
source exchange, and no client does that yet.

eMuleQt registers, and is woken, only on its own server. As a requester for a peer on
another server it sweeps: it sends `SYNC2` to its own server, then to up to 8 listed servers
whose UDP flags carry `0x40000`, 2 per server, 4 s apart. That finds a target only when the
target is logged in to, or registered with, one of the swept servers. It ignores a `SYNC`
for a hash it did not ask for.

Clients logged in to the rendezvous server need no standing registration when it offers the
wake-up. Only foreign targets keep one.

**Who keeps a standing registration today.** eMuleQt registers only while all of these hold:
NAT traversal on, firewalled (eD2K LowID and Kad not open), a public IPv6 it trusts (its only
data path is TCP over IPv6, so an IPv4-only LowID never takes part), and a server with
`0x40000`. It then registers IPv4, plus IPv6 when the server has one, with a keepalive every
60 s, for the whole session. On a server with `0x200000` it keeps none: it sets the login bit
whenever NAT traversal is on, also before it trusts an IPv6, and ignores a wake while it has
no data path (the requester then gets `FAILED 0x01` after the 3 s wake timeout). eMule, aMule and
other clients do not speak `PR_NAT`.

## Comparison with the other two schemes

| | `PR_NAT` (eNode-go) | Lugdunum NAT callback | ed2k-server hole punch |
| --- | --- | --- | --- |
| Announced by | `0x40000`, `ST_NAT_PORT`; wake-up `0x200000` (server flags and login bit) | `0x1000` (server flags and login bit) | `0x20000`; extension `0x100000` |
| Servers | eNode-go | Lugdunum eserver 17.14/17.15, ed2k-server ≥ 0.9.85, eNode-go (after v0.5.1) | ed2k-server |
| Request | UDP `SYNC2` to the rendezvous port | UDP `0xA6`, server-key obfuscated | TCP `0x60` on the login session |
| Peer key | user hash | LowID | LowID |
| Who learns the other's endpoint | both, in one step | the target only; the requester learns it only if the target sends its own `0xA6` | both, with user hash and role |
| Address- or port-restricted NAT (most home routers) | works | usually fails until the reverse request | works |
| Symmetric NAT | fails | fails | fails |
| IPv6 | yes, preferred when both registered one | no | no |
| Cross-server | yes (same rendezvous server; eMuleQt sweeps up to 8 servers as requester) | no | no |
| Freshness of the endpoint | the last keepalive, at most a TTL old | the request itself, always fresh | the last `0x9F`, up to 600 s old; fresh with the extension |
| Waking the target | logged in here: TCP `OP_NAT_WAKE`, then its `REGISTER`; foreign: its standing UDP mapping | TCP `0x37`, or UDP `0xA7` within 19 s (eNode-go) of its own request | `0x61` over TCP; with the extension `0x37`, then the target's `0x9F` |
| Standing traffic while idle | none with the wake-up; else keepalive every 60 s per family | none | `0x9F` every ~60 s |
| Server memory per idle client | none with the wake-up (one bool in existing padding); else 146 bytes per single-family client (measured) | none (eNode-go: one bool in existing padding) | one port and timestamp per client |
| Failure feedback | `FAILED` with a reason | none | `0x62` with a reason |
| Data on the punched path | not defined | not defined | not defined |
| Clients | eMuleQt | eMuleQt, aMule, NeoLoader, NeoMule | eMuleQt, aMule |

What follows from the table:

- `PR_NAT` and ed2k-server's punch solve the restricted-NAT case, because both peers punch.
  Lugdunum's callback does not, unless the target answers with its own request (aMule and
  eMuleQt do).
- `PR_NAT` is the only scheme that covers IPv6 firewalls and peers on different servers.
- Lugdunum's callback and `PR_NAT` with the wake-up have no standing traffic and no
  per-client state. Lugdunum's callback is the only one most clients speak.
- On eNode-go, eMuleQt tries `PR_NAT` first when it knows the peer's hash, and Lugdunum's
  callback for hashless `OP_FOUNDSOURCES` rows or when `PR_NAT` produced no endpoint.
  eMuleQt uses Lugdunum's callback only for an odd target LowID over an IPv4 session, so on
  an IPv6 session there is no Lugdunum fallback.

## Sending cost

Sizes are on the wire, including the 28-byte IPv4 + UDP header (48 bytes for IPv6), and
exclude Ethernet framing.

### `PR_NAT`

| Message | Payload | IPv4 datagram | IPv6 datagram | When |
| --- | --- | --- | --- | --- |
| `REGISTER` | 6 + 16 | 50 B | 70 B | every 5 s until acked |
| register ack | 6 + 6 / 6 + 18 | 40 B | 72 B | once |
| `KEEPALIVE` | 6 | 34 B | 54 B | every 60 s per family |
| `PING` | 6 | 34 B | 54 B | answer to each keepalive |
| `SYNC2` | 6 + 36 | 70 B | 90 B | per attempt, up to 3 times |
| `SYNC` / `SYNC_EX` | 6 + 26 / 27 | 60 / 61 B | – | 2 per accepted `SYNC2` |
| `SYNC_IPV6` | 6 + 39 | – | 93 B | 2 per accepted `SYNC2` |
| `FAILED` | 6 + 17 | 51 B | 71 B | instead of the two `SYNC`s |

**Standing cost per registered client and family:** 1 keepalive and 1 ping a minute (3 of
each before 2026-10-25, with a 20 s keepalive).

| | Per minute, each way | Per hour, each way | Per day, each way |
| --- | --- | --- | --- |
| IPv4 | 34 B | 2.0 KB | 49 KB |
| IPv6 | 54 B | 3.2 KB | 78 KB |
| Dual-stack client | 88 B | 5.3 KB | 127 KB |

**Server, standing cost by number of registered IPv4 clients:**

| Registered | Datagrams per second, in + out | Bandwidth, each way | Per day, each way |
| --- | --- | --- | --- |
| 1,000 | 17 + 17 | 0.6 KB/s (4.5 kbit/s) | 49 MB |
| 10,000 | 167 + 167 | 5.7 KB/s (45 kbit/s) | 490 MB |
| 100,000 | 1,667 + 1,667 | 57 KB/s (453 kbit/s) | 4.9 GB |

The bandwidth is small. The packet rate matters more. In eNode-go a keepalive costs one index
lookup, about 40–140 ns at 100,000 entries (`TestNatIndexCost`; it was a 3.8 ms scan of the whole registry
before 2026-10-25). With the wake-up, none of this applies to clients logged in to the
server.

**One pairing:** 70 B in and 120 B out over IPv4 (122 B with `SYNC_EX`; 90 B in and 186 B
out over IPv6), up to three times if the requester repeats. That is about 1.7 bytes out per
byte in over IPv4 and 2.1 over IPv6, all of it to the two endpoints the
server already holds for those hashes. Only the requester's endpoint comes from the request,
and only when that slot was empty: a spoofed `SYNC2` can make the server send one `SYNC` to
the forged source address, much as any register would.

**Memory:** 146 bytes per client with one family, measured by `TestNatIndexCost` on 100,000
IPv4 entries, the index included (hash key, entry with both family slots inline, each with a
1-byte socket index in its padding, endpoint key). A second family adds only its index
entry. It was 171 bytes
without an index, when each candidate was three allocations. Only clients that register cost
anything.

**With the wake-up (a target logged in to the rendezvous server):**

| | Bytes | When |
| --- | --- | --- |
| standing | an empty TCP `OP_OFFERFILES` (6 + 4 B) after 20 min of TCP silence, about 0.5 B a minute | instead of 68 B a minute (both ways) per IPv4 family |
| `OP_NAT_WAKE` | 6 + 1 B in the existing TCP session | once per attempt |
| target `REGISTER` + ack | 50 + 40 B over IPv4, 70 + 72 B over IPv6 | once per requested family |
| requester's extra `REGISTER` + ack | 50 + 40 B over IPv4 | once, on a dual-stack requester |
| `SYNC` pair | as above | once |

The empty `OP_OFFERFILES` replaces the keepalive's second job: on eNode-go a `PR_NAT`
keepalive also counts as activity for the client's eD2K session, which is closed after
3600 s without any. eNode-go treats offers as additive, so an empty one changes nothing.
Server memory while an attempt is in flight is one small entry per woken target, gone after
the pairing or 3 s.

### The other two, for comparison

| | Lugdunum callback | ed2k-server hole punch |
| --- | --- | --- |
| Standing, per client | nothing | `0x9F` (2 + 16 B payload, 46 B datagram; 54–69 B obfuscated on an extension server) every 60 s, unanswered: 46 B/min up, 2.8 KB/h |
| Request | `0xA6`, 10 B plaintext + 8–23 B obfuscation, 46–61 B datagram; eMuleQt sends up to 9, 5 s apart | TCP `0x60`, 6 + 6 B in the existing session |
| Notice to the target | TCP `0x37`, 6 + 11 B (27 with the hash) in the existing session; or UDP `0xA7`, 49–65 B | TCP `0x61`, 6 + 29 B to both peers, resent at +1.2 s and +3 s: up to 6 × 35 B |
| Mutual round | the target sends its own `0xA6`, and the requester gets the same notice | not needed |

Lugdunum's callback uses the least traffic, because the eD2K TCP session it relies on already
exists. ed2k-server's standing `0x9F` has the same 60 s interval and costs two thirds of `PR_NAT`'s
keepalive traffic per client (46 B a minute against 68 B both ways), because it gets no
answer; obfuscated on an extension server it costs about as much. The port it gives peers
can be up to 600 s old.
With a 60 s keepalive the `PR_NAT` endpoint is at most a minute old, and the 90 s TTL means
it is never used once older than that. The keepalive also holds the
client's NAT mapping open, and that is the trade-off of the 60 s interval: RFC 4787 asks
routers to keep an idle UDP mapping for at least 2 minutes, but some drop it after 30–60 s.
Behind such a router a foreign target's `SYNC` can arrive after the mapping is gone. The
answered `PING` helps: many routers keep a mapping that saw traffic both ways longer.
Targets logged in to the rendezvous server are not affected; the wake-up gives them a fresh
mapping for each attempt.

## Waking a local target

Implemented in eNode-go after v0.5.1 (`ed2k/natwake.go`) and eMuleQt after v0.6.30. It does
for `PR_NAT` what ed2k-server's extension does with `0x37`: the server reaches a target that
is logged in to it over the eD2K TCP session, so the target needs no standing registration.

1. **Login.** The client sets `SRVCAP_NAT_WAKE` (`0x200000`) in `CT_SERVER_FLAGS` (eMuleQt:
   whenever NAT traversal is on, so a data path found after login needs no new login). The server
   remembers it per session (eNode-go: one bool in existing padding, so a session does not
   grow) and advertises `0x200000` in its TCP and UDP flags. A client keeps no standing
   registration only when both are set.
2. **SYNC2.** When the target hash has no live candidate in a family the requester has, and
   a session that set the bit is logged in under it, the server sends that session
   `OP_NAT_WAKE` with the requester's families. It asks for IPv6 only when it knows an IPv6
   of the target (the session's address or its `CT_MOD_IP_V6`). It answers the requester
   nothing yet, and remembers (target, requester, `connAck`, the socket the SYNC2 came in on).
3. **Repeats.** A repeated SYNC2, or one from a second requester, joins the wait and does not
   wake again (at most 4 requesters per target). It wakes again only for a family not asked
   for yet.
4. **Target.** On `OP_NAT_WAKE` the client sends one `REGISTER` per requested family it can
   offer, IPv6 first, from its peer-facing UDP socket to the rendezvous port. A client that
   is not a useful target at the moment (not firewalled, no data path) ignores it.
5. **Pairing.** A `REGISTER` from the target in a requested family completes the wait: the
   server sends the ack, then the two `SYNC`s as for any SYNC2, preferring IPv6. The
   target's two `REGISTER`s race, so when IPv6 was asked for and the IPv4 one arrives first,
   the server waits up to 500 ms more for the IPv6 one, then pairs on what it has (eMuleQt
   sends IPv6 first, but the IPv4 one can still arrive first). The requester's `SYNC`
   leaves from the socket and address its SYNC2 arrived on, which its NAT mapping expects,
   and the target's from the socket its `REGISTER` arrived on. This holds also when the
   pairing comes after the 500 ms wait or at the timeout.
6. **Timeout.** If no `REGISTER` in a family the requester has arrives within 3 s, every
   waiting requester gets `FAILED 0x01`. A requester treats it like any `FAILED` and tries another path.
7. **Limits.** At most 4096 targets wait at once; beyond that a SYNC2 fails at once, as
   without the wake. A wake needs the target's TCP session, so it is never sent for a foreign
   target, and in restricted mode (`serverIndependent` off) only for a requester logged in
   here too.
8. **Abuse.** A SYNC2 is UDP, so its source can be forged. The worst a forger gets is one
   7-byte TCP packet to a target and its `REGISTER`, one wait per target at a time (with at
   most one extra wake per newly requested family), and a `FAILED` or, if the target
   registers, a `SYNC` to the forged address. A new wait can start as soon as one ends.
   A fifth requester for a waiting target gets `FAILED` at once.

The target's registration then lives one TTL like any other and is not kept alive.

## Implementation checklist

**Server:**

- [ ] Envelope with LE size; BE endpoint fields.
- [ ] Per-hash registry, one candidate per family, observed source only, TTL with sweep.
- [ ] REGISTER checks: session address when logged in here, no takeover of a live candidate
      from another IP.
- [ ] Ack with the server's own public endpoint per family (`0xE4` / `0xEC`).
- [ ] Keepalive matched by source IP and port, through an index; `PING` on a match; counts as
      session activity.
- [ ] `PR_NAT` taken before any deobfuscation and answered in plaintext on every port.
- [ ] `SYNC2`: auto-register, `FAILED` 1/2/3, IPv6 first, both `SYNC`s with `connAck`, `EX`
      only to a versioned receiver.
- [ ] Treat a candidate past the TTL as gone on every read, not only at the sweep.
- [ ] Forward to the target from the socket its candidate arrived on, and to an IPv6 target
      from the announced IPv6 address; answer the requester from its SYNC2's socket.
- [ ] Advertise `0x40000` only when unrestricted pairing is on, in the TCP and UDP flags.
- [ ] Wake-up: `0x200000` in both flag words and `ST_NAT_PORT`; remember the login bit; on a
      SYNC2 for an unregistered local target send `OP_NAT_WAKE`, pair on its `REGISTER`,
      `FAILED 0x01` after 3 s; dedupe repeats; cap the waiting entries.

**Client:**

- [ ] Detect `0x40000` and `0x200000`; read `ST_NAT_PORT`, default `2004`.
- [ ] Wake-up: set login bit `0x200000`; on a server with the flag keep no registration,
      answer `OP_NAT_WAKE` with one `REGISTER` per family, and send an empty `OP_OFFERFILES`
      after 20 min of TCP silence.
- [ ] While firewalled: `REGISTER` per family from the peer-facing UDP socket, backing off
      when unanswered; follow the ack's endpoint; keepalive inside the TTL; re-register at
      the default endpoint when pings stop.
- [ ] `SYNC2` with a fresh `connAck`; repeat a few times; handle `SYNC`, `SYNC_EX`,
      `SYNC_IPV6` and `FAILED`.
- [ ] Punch on `SYNC` from both sides; match the peer by `connAck` or an equivalent check.
- [ ] Send one request per target per scheme. Fall back to another scheme only after this one
      failed or timed out.
