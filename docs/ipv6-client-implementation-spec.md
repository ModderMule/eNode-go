# IPv6 Client Implementation Spec (eNode-go)

How an eD2K/eMule client connects to eNode-go over IPv6 and exchanges IPv6
sources. This describes the **server's observable behaviour** — everything here is
implemented in eNode-go and byte-compatible with the eMuleAI / eMuleQt MOD-tag
scheme (`CT_MOD_*`, tag family `0xA0`–`0xAF`).

An IPv4-only client needs to do nothing: every classic packet is byte-identical
to the pre-IPv6 server. IPv6 is entirely additive and opt-in.

---

## 0. Constants

| Name | Value | Where |
|---|---|---|
| `CT_MOD_IP_V6` | tag `0xAE`, type `TAGTYPE_HASH` (0x01), 16 bytes | `OP_LOGINREQUEST` (client→server) |
| `CT_MOD_SVR_IP_V6` | tag `0xAF`, type `TAGTYPE_HASH`, 16 bytes | `OP_SERVERIDENT` (server→client) |
| `CT_MOD_YOUR_IP` | tag `0xAD`, type `TAGTYPE_HASH`, 16 bytes | `OP_SERVERIDENT` (server→client) — the IPv6 the server observes *you* on (§3a) |
| `ST_IPV6_STATUS` | tag `0xAB`, type `TAGTYPE_UINT8` (0x09) | `OP_SERVERIDENT` (server→client) — `IPV6ST_*` bitfield (§3a) |
| `IPV6ST_HAVE` | `0x01` | `ST_IPV6_STATUS` bit: the server holds a public IPv6 for your session |
| `IPV6ST_REACHABLE` | `0x02` | `ST_IPV6_STATUS` bit: that address is treated as reachable — you are published as a v6 source |
| `IPV6ST_PROBED` | `0x04` | `ST_IPV6_STATUS` bit: the verdict came from a real dial-back, not a trust default |
| `SRV_TCPFLG_IPV6` | `0x00004000` | `OP_IDCHANGE` / `OP_SERVERIDENT` flags word |
| `SRV_UDPFLG_IPV6` | `0x00004000` | `OP_GLOBSERVSTATRES` UDP flags word |
| `SRVCAP_IPV6` (optional) | `0x1000` | `CT_SERVER_FLAGS` (0x20) login tag |
| IPv6 source sentinel | ClientID `0xFFFFFFFF` | `OP_FOUNDSOURCES(_OBFU)`, `OP_GLOBFOUNDSOURCES` |
| `OP_GETSOURCES_IPV6` | `0x24` | client→server, TCP |
| `OP_FOUNDSOURCES_IPV6` | `0x25` | server→client, TCP |
| `OP_GLOBGETSOURCES_IPV6` | `0xA5` | client→server, UDP |
| `OP_GLOBFOUNDSOURCES_IPV6` | `0xA6` | server→client, UDP |
| `OP_CALLBACKREQUESTED_IPV6` | `0x26` | server→client, TCP |
| `OP_NAT_REGISTER_IPV6` | `0xEC` (under `PR_NAT 0xF1`) | server→client, UDP |
| `OP_NAT_SYNC_IPV6` | `0xED` (under `PR_NAT 0xF1`) | server→client, UDP |
| `SRV_TCPFLG_NAT_RENDEZVOUS` | `0x00008000` | `OP_IDCHANGE` / `OP_SERVERIDENT` flags word |
| `ST_NAT_PORT` (server NAT UDP port) | tag `0x9D`, type `TAGTYPE_UINT16` | `OP_SERVERIDENT` (server→client) |

**Byte order:** every 16-byte IPv6 field is the raw `in6_addr` in network byte
order (big-endian, the order `inet_pton` produces and a textual `2001:db8::1`
reads left to right). No swapping. Send a genuine IPv6 in the 16-byte field and an
IPv4 in the existing 32-bit ClientID/IP fields — never an IPv4-mapped
(`::ffff:a.b.c.d`) form in a 16-byte field, since it will not compare equal to the
plain IPv4 on the peer side.

---

## 1. Transport: reaching the server over IPv6

eNode-go binds a **dual-stack** listener (single socket, `[::]`, `IPV6_V6ONLY=0`)
when `ipv6.enabled` (the default). It accepts both IPv4 and IPv6 client
connections on the same TCP and UDP ports. No separate v6 port.

A client that wants to connect over IPv6 needs, on its own side:

- an `AF_INET6` (dual-stack) socket for the server TCP and UDP connections;
- `AAAA` DNS resolution for a server given by hostname;
- a 16-byte IPv6 field in its server list / `server.met` equivalent, not a
  `uint32` IP.

A client that connects over IPv4 keeps working unchanged and may still advertise
its IPv6 (see §2) so it can be published as a v6 source.

---

## 2. Announcing IPv6 capability to the server

Two independent signals; either marks the session as "understands the IPv6 source
formats" (the server calls this *sentinel-safe*):

1. **Connect over IPv6.** A session whose TCP connection arrives on an IPv6
   address is treated as v6-capable automatically.
2. **Send `CT_MOD_IP_V6` in `OP_LOGINREQUEST`.** Add a hash tag carrying your
   public IPv6 and bump the login tag count. This is exactly what eMuleAI sends
   (`ServerConnect.cpp`).

Login tag on the wire (classic tag format — the server has not yet parsed your
`SRVCAP_NEWTAGS` when it reads the login tags, so use classic form):

```
01            TAGTYPE_HASH
01 00         name length = 1 (LE uint16)
AE            CT_MOD_IP_V6
<16 bytes>    your public IPv6, network byte order
```

Only send it for a **genuinely public** IPv6 (global unicast, not loopback,
link-local `fe80::/10`, or ULA `fc00::/7`). The server validates and drops a
non-public value, but still treats the tag's presence as the capability signal.

Optionally also set `SRVCAP_IPV6 (0x1000)` in the `CT_SERVER_FLAGS (0x20)` login
tag. This lets you announce "I speak the extension" even before you have a public
IPv6 to put in `0xAE`. The server reads `CT_SERVER_FLAGS` as a uint32.

> **Hard coordination rule.** Do **not** advertise v6 capability (connect over
> IPv6, or send `CT_MOD_IP_V6`) unless your client also implements the sentinel
> parser in §4. A sentinel-safe session may receive `0xFFFFFFFF` sentinel sources
> inside a classic `OP_FOUNDSOURCES`; a client that advertises capability but
> cannot parse the sentinel will desync its source list.

### ID assignment when there is no usable HighID

An ed2k ClientID is 32 bits and a HighID *is* the packed IPv4, first octet in the
low byte. Two kinds of session therefore cannot be given one, and eNode-go assigns
both a **LowID** unconditionally — without even running the IPv4 dial-back, whose
answer could not change the outcome:

1. **No IPv4 at all** — an IPv6-only session. It is reached via its IPv6, published
   as a v6 source, and can drive and receive **IPv6 LowID callbacks** (§7).
2. **An IPv4 ending in `.0`** — `203.0.113.0` packs to `0x007100cb`, at or below
   `0x00ffffff`, which is exactly the range a client reads back as a LowID. eMule
   assumes servers behave this way; the comment above its own `IsLowID` says so
   outright: *"we now know the servers just give `*.*.*.0` users a lowID"*
   (`srchybrid/otherfunctions.h:448`). Such a client is reached by IPv4 LowID
   callback like any other LowID, and its `observedClientIPv4` is `0` (§3a) — the
   field has no encoding for an address in that range.

A dual-stack client with a routable IPv4 still gets a HighID as usual.

---

## 3. Reading the server's IPv6 capability

- **Flags word.** `SRV_TCPFLG_IPV6 (0x4000)` in `OP_IDCHANGE` / `OP_SERVERIDENT`
  and `SRV_UDPFLG_IPV6 (0x4000)` in `OP_GLOBSERVSTATRES` indicate the server
  supports the IPv6 extension. Treat unknown flag bits as reserved and ignore
  them, as eMule does.
- **Server's own IPv6.** `OP_SERVERIDENT` carries a `CT_MOD_SVR_IP_V6 (0xAF)`
  hash tag (16 bytes) when the server has a public IPv6. Parse it position-
  agnostically among the ident tags; unknown tags before/after it must be
  consumed by type and skipped (a `TAGTYPE_HASH` tag is 16 bytes). This is
  informational — you still reach the server on the same address you connected to.
- **NAT-rendezvous capability.** `SRV_TCPFLG_NAT_RENDEZVOUS (0x8000)` in the flags
  word signals the server offers **server-independent** (cross-server / serverless)
  PR_NAT hole-punch rendezvous (§9): it will pair two registered clients regardless
  of which eD2K server, if any, they are logged into. When set, `OP_SERVERIDENT` also
  carries `ST_NAT_PORT (0x9D)`, a `TAGTYPE_UINT16` tag with the server's NAT-rendezvous
  UDP port (so you need not assume the default `2004`). Both are absent when the
  operator has turned the feature off; then only same-server LowID↔LowID is served.

---

## 3a. Learning your own addresses

The server sees the address you actually reach it from. It reports that back, which
is the only reliable way for you to know it: your local interface addresses are not
what a peer observes, and with RFC 4941 temporary addresses plus multiple delegated
prefixes you cannot tell locally *which* of your IPv6 addresses egressed.

### Your IPv4 — `OP_IDCHANGE`

eNode-go sends `OP_IDCHANGE` in eMule's full documented 16-byte layout:

```
uint32  newClientID
uint32  serverTCPFlags
uint32  primaryTCPPort     // the server's own listening port; eMule ignores this word
uint32  observedClientIPv4 // the IPv4 the server sees you on, packed as an ed2k ID
```

Read `observedClientIPv4` only when the packet is at least 16 bytes — older servers
send 8. This is what stock eMule already does (`srchybrid/ServerSocket.cpp:306-315`),
and it matters most on a **LowID**, where the ID tells you nothing about your
address: eMule feeds this word straight to `SetPublicIP()`. On a HighID the value
equals `newClientID`, since a HighID *is* the packed IPv4.

`observedClientIPv4` is `0` when the server has no routable IPv4 for you — an
IPv6-only session, or an address whose packed form would be indistinguishable from a
LowID. Treat `0` as "unknown", never as an address. Both cases are also assigned a
LowID (§2, "ID assignment when there is no usable HighID"), so `newClientID` and this
word always agree about which kind of session you are in.

### Your IPv6 — `CT_MOD_YOUR_IP (0xAD)` in `OP_SERVERIDENT`

A 16-byte `TAGTYPE_HASH` tag carrying the IPv6 the server observed the session
arriving on. Parse it position-agnostically among the ident tags, exactly like
`CT_MOD_SVR_IP_V6` (§3).

**The tag is only ever an observed address.** It is sent only for a session that
actually connected over IPv6, and only when that peer address is public global
unicast. A session that connects over IPv4 and advertises `CT_MOD_IP_V6` receives
**no** tag — echoing your own claim back would tell you nothing you did not already
know. Prefer this value over any locally-guessed source address when you populate
your own `CT_MOD_IP_V6`, and over a value reflected by a peer's client-to-client
`CT_MOD_YOUR_IP`: the server is the more stable observer.

### Your IPv6 status — `ST_IPV6_STATUS (0xAB)` in `OP_SERVERIDENT`

A `TAGTYPE_UINT8` bitfield answering the question reflection cannot answer for a
v4-connected client: *is the IPv6 I advertised actually working?*

| Bit | Meaning |
|---|---|
| `IPV6ST_HAVE (0x01)` | the server holds a public IPv6 for this session (from your `CT_MOD_IP_V6`, or from a v6 connection) |
| `IPV6ST_REACHABLE (0x02)` | that address is treated as reachable on the port you advertised — you are published as an IPv6 source |
| `IPV6ST_PROBED (0x04)` | the reachability verdict came from an actual dial-back, not a trust default |

Unset bits mean "no", never "unknown": the tag is **omitted entirely** when the
server has no verdict to report, so every bit in a tag you receive is meaningful.
The tag is absent when v6 source publication is off, when the server holds no IPv6
for you, and on an ident sent before you have logged in (an `OP_GETSERVERLIST`
before `OP_LOGINREQUEST` also draws an `OP_SERVERIDENT`).

What the combinations mean:

| Session | Bits | Reading |
|---|---|---|
| connected over IPv6 | `HAVE\|REACHABLE` | proven by the connection itself; no dial-back was needed |
| connected over IPv4, dial-back succeeded | `HAVE\|REACHABLE\|PROBED` | verified — you are reachable as an IPv6 source |
| connected over IPv4, dial-back failed | `HAVE\|PROBED` | verified unreachable — your v6 port is firewalled or the address is wrong, and you are **not** published as a v6 source |
| `tcp.probeIPv6` off on the server | `HAVE\|REACHABLE` | assumed, not tested |
| (tag absent) | — | the server has no verdict; assume nothing |

`IPV6ST_PROBED` is the bit that keeps the signal honest. Without it,
`REACHABLE` may be an assumption, so do not report "IPv6 verified" to a user
unless `PROBED` is also set.

### Compatibility

All three fields are additive and skippable. eMule only lower-bounds the
`OP_IDCHANGE` size and never rejects a longer packet, and its `OP_SERVERIDENT` tag
loop dispatches on the tag *name*, consuming names it does not know. Both tags use
value types the reference reads by fixed length (`TAGTYPE_HASH` = 16 bytes,
`TAGTYPE_UINT8` = 1 byte) and are appended after the classic server tags, so a
client that ignores them parses exactly as before.

---

## 4. Receiving IPv6 sources

Two formats. Implement **both** to be fully interoperable.

### 4a. Sentinel form — inside classic `OP_FOUNDSOURCES` / `OP_FOUNDSOURCES_OBFU`

The server sends this to a sentinel-safe session (see §2). A source whose only
routable address is IPv6 (a v6-only source, or a LowID source with a reachable
IPv6) is encoded with the ClientID sentinel `0xFFFFFFFF` followed by 16 IPv6
bytes. Per-source layout:

```
uint32 clientId                       // 0xFFFFFFFF marks an IPv6 source
uint16 port
[_OBFU only]        uint8  cryptOptions
[_OBFU && (cryptOptions & 0x80)]  uint8[16] userHash
[clientId == 0xFFFFFFFF]          uint8[16] ipv6   // ALWAYS the last field
```

The 16 IPv6 bytes come **after** the obfuscation fields. When you read
`clientId == 0xFFFFFFFF`, read the 16 bytes and create a source with that IPv6 and
the given port. A source with a real HighID (routable IPv4) is never sent as a
sentinel — you get its IPv4 form and should prefer it.

> A client that does not implement this branch **must not** be sentinel-safe (do
> not connect over IPv6 and do not send `CT_MOD_IP_V6`). Skipping the ClientID
> without consuming the 16 bytes desyncs the rest of the source list.

### 4b. Tag-block form — `OP_FOUNDSOURCES_IPV6` (0x25) / `OP_GLOBFOUNDSOURCES_IPV6` (0xA6)

The richer, unconditionally-safe format. You opt in by sending the request opcode;
the server replies in the extended layout only to a client that asked for it, so
there is no desync risk for anyone else.

Request (`OP_GETSOURCES_IPV6 0x24` TCP, `OP_GLOBGETSOURCES_IPV6 0xA5` UDP): same
payload as the classic `OP_GETSOURCES2` — `hash16` + file size (a zero `uint32`
size means a `uint64` size follows). UDP may repeat `hash16 + size` per file.

Reply:

```
hash16 fileHash
uint8  count
per source:
    uint32 clientId       // real ClientID, or 0xFFFFFFFF for a v6-only source
    uint16 port
    uint8  tagCount
    tags…                 // standard eD2K tags, uint8-counted
```

Recognised tags in the block:

| Tag | Value / type | Meaning |
|---|---|---|
| `CT_MOD_IP_V6` | `0xAE`, `TAGTYPE_HASH` (16 bytes) | the source's public IPv6 |

A source with no reachable IPv6 has `tagCount = 0` (just `clientId`+`port`), so the
block is a strict superset of the classic list. **Skip unknown tags by type** —
the block is forward-compatible and may gain tags (e.g. buddy IPv6, crypt options)
later.

> **Tag-type safety.** The block uses only `TAGTYPE_HASH` / `TAGTYPE_UINT8` and
> other length-determinable types — never `TAGTYPE_BOOL (0x05)` or
> `TAGTYPE_BOOLARRAY (0x06)`, which some parsers cannot length-skip.

### UDP framing

The server sends **one file block per datagram** for `OP_GLOBFOUNDSOURCES`. Do not
assume the vanilla `count * (4 + 2)` skip stride when coalescing — a sentinel
source carries extra bytes. The sentinel form is only ever sent over UDP to a
sender whose query arrived over IPv6; the tag-block form is sent only in reply to
`OP_GLOBGETSOURCES_IPV6`.

---

## 5. Choosing an address to connect to a source

When a source offers both an IPv4 (HighID) and an IPv6, prefer the family you have
working connectivity on; the server prefers giving you the IPv4 form when you have
a usable IPv4, and the IPv6 sentinel/tag when the source has no routable IPv4. A
v6-only source (`clientId == 0xFFFFFFFF`) is reachable only over IPv6.

---

## 6. What the server does not do

- Nothing NAT-related is scoped out any more: `PR_NAT` hole-punching is dual-stack —
  see **§9**. (When `natTraversal.ipv6` is set to `false`, the server declines IPv6
  `PR_NAT` datagrams and the family is IPv4-only, exactly as it was before v6 support.)
- Self-address discovery is no longer scoped out either: the server reports the IPv4
  and IPv6 it observes you on, plus its verdict on whether your IPv6 is reachable —
  see **§3a**. What it still does not do is reflect an address it has not observed:
  a v4-connected session gets no `CT_MOD_YOUR_IP`, only the status bitfield.
- The `PR_NAT` `OP_NAT_REGISTER*` acks are **not** a reflection channel. They carry
  the *server's* endpoint so you know where to punch; the observed source of your
  register is recorded server-side as a candidate but never sent back (§9).

---

## 7. IPv6 LowID callbacks

A LowID callback lets a firewalled **target** be reached: a **requester** asks the
server to tell the target to connect *back* to the requester. Classic
`OP_CALLBACKREQUESTED (0x35)` carries `uint32 ip + uint16 port` (the requester's
IPv4), so it only works when the requester is directly reachable over IPv4 (HighID).
A requester whose only routable address is IPv6 — v6-only, or LowID over IPv4 —
could not be called back at all. eNode-go now closes that gap.

### Request (unchanged)

The requester still sends `OP_CALLBACKREQUEST (0x1C)` `<target LowID:uint32>`. The
LowID is the server-assigned 32-bit id; it is family-agnostic and needs no change.

### The server's family choice

The server picks the callback family from the **requester's** reachability, as two
independent checks:

1. If the requester has a HighID (a routable IPv4), the server sends the classic
   `OP_CALLBACKREQUESTED (0x35)` — byte-identical to before.
2. Otherwise (requester LowID over IPv4, or IPv4 `0`), if the requester has a
   **reachable public IPv6** and the target session is **v6-capable** (§2), the
   server sends `OP_CALLBACKREQUESTED_IPV6 (0x26)` so the target calls back over
   IPv6.
3. If neither applies, the server sends `OP_CALLBACKFAILED (0x36)`.

### `OP_CALLBACKREQUESTED_IPV6 (0x26)` — server → target

```
uint8      opcode = 0x26
uint8[16]  ipv6        // the requester's public IPv6, network byte order
uint16     port        // the requester's port (LE)
```

It is the classic packet widened from a 4-byte IPv4 to a 16-byte `in6_addr`, with
**no** crypt-options/userhash trailer (eNode-go's classic `0x35` emitter has none
either). On receipt, build the callback client from the 16 IPv6 bytes and the port
and connect to it over IPv6, exactly as you would `TryToConnect()` on the IPv4
address from `0x35`.

> **Capability gate.** The server only sends `0x26` to a session it knows is
> v6-capable (connected over IPv6, or sent `CT_MOD_IP_V6` at login — §2). A client
> that is not v6-capable never receives it, and a legacy client drops the unknown
> `0x26` opcode in its `ProcessPacket` default, so there is no desync risk.

---

## 8. IPv6 peer servers in `OP_SERVERLIST`

`OP_SERVERLIST (0x32)` advertises the other servers this node knows. The classic
packet is `<v4count:uint8>` then `v4count × (<ip:uint32 LE><port:uint16 LE>)`.
eNode-go widens it with a **trailing IPv6 block**, appended after the v4 entries:

```
uint8   v4count
v4count × ( uint32 ip (LE)   + uint16 port (LE) )      // classic block, unchanged
uint8   v6count                                         // present only when appended
v6count × ( uint8[16] ipv6 (network order) + uint16 port (LE) )
```

The trailing block is emitted only when IPv6 publication is on
(`ipv6.publishSources`) **and** at least one configured peer server carries a public
IPv6. When absent, the packet is byte-identical to the classic form — not even a
zero `v6count` byte is added.

### Why this needs no per-session capability gate

Unlike the source sentinel (§4a), which is *inline* and would desync a v4-only
parser, the server-list v6 block is pure **trailing data** after a self-terminating
`uint8` count. A v4-only parser reads exactly `v4count` entries and ignores the
rest (all three surveyed clients simply debug-dump it), so the same widened packet
is safe to send to every session. A v6-aware client, after consuming the `v4count`
entries, checks whether a `<v6count>` byte remains and, if so, reads that many
`<ipv6:16><port:2>` entries and builds each server from the 16-byte address.

### Configuring v6 peer servers

A `servers[].ip` entry in `enode.config.yaml` may be an IPv4 dotted-quad or a
**public** IPv6 literal. Non-public v6 (loopback, link-local `fe80::/10`, ULA
`fc00::/7`) and malformed entries are dropped at load and never advertised.

---

## 9. NAT traversal hole-punching (`PR_NAT`)

`PR_NAT (0xF1)` is a UDP hole-punch rendezvous service: the server relays each of
two firewalled peers the other's public endpoint so they can punch a hole directly
to each other. It covers the cases a direct connect or a callback cannot:

- **LowID ↔ LowID (IPv4).** Two peers both behind NAT with no reachable IPv4. The
  classic callback (`0x35`) needs the *requester* reachable, so it fails when both
  are LowID. Hole-punching does not.
- **Firewalled IPv6 ↔ firewalled IPv6.** Two peers each behind a stateful IPv6
  firewall. Neither can accept an inbound connection, so neither direct-reach nor the
  `0x26` callback (§7) works. This is the v6 analogue of LowID↔LowID.

This protocol exists only in eNode-go today; no C++ client implements it yet. This
section is the wire contract to implement against.

### Framing and byte order

Every `PR_NAT` datagram is `[0xF1][size:4 LE = payloadLen+1][opcode:1][payload]` —
the same envelope as `PR_ED2K`, but with its own opcode namespace (these opcodes are
interpreted only after the `0xF1` byte, so they do **not** collide with the
`PR_ED2K` opcodes `0x24/0x25/0x26`). A bare **1-byte** datagram (any value) is a
legacy keepalive.

> **Byte order is big-endian for every endpoint field in `PR_NAT`** — IP *and*
> port. This is deliberately unlike the LE convention used elsewhere in eD2K
> (including the `0x26` callback's LE port). Keep `PR_NAT` internally BE.

### Opcodes

| Opcode | Value | Dir | Meaning |
|---|---|---|---|
| `OP_NAT_REGISTER` | `0xE4` | c→s / s→c | register request (hash); also the v4 register **ack** |
| `OP_NAT_REGISTER_EX` | `0xE3` | c→s | register request carrying a client version byte |
| `OP_NAT_REGISTER_IPV6` | `0xEC` | s→c | **v6 register ack** (new) |
| `OP_NAT_KEEPALIVE` | `0xE6` | c→s | keepalive (or a bare 1-byte datagram) |
| `OP_NAT_PING` | `0xE2` | s→c | keepalive ack |
| `OP_NAT_SYNC2` | `0xE9` | c→s | pair my hash with a target hash |
| `OP_NAT_SYNC` | `0xE1` | s→c | peer endpoint, v4 |
| `OP_NAT_SYNC_EX` | `0xE7` | s→c | peer endpoint, v4, + peer version |
| `OP_NAT_SYNC_IPV6` | `0xED` | s→c | **peer endpoint, v6** (new) |
| `OP_NAT_FAILED` | `0xE5` | s→c | pairing failed (reason byte) |

`0xE8/0xEA/0xEB/0xEF` (REPING/DATA/ACK/RST) are reserved and unused by eNode-go.

### Payload layouts (byte-exact)

```
REGISTER request  (c→s, 0xE4)   hash:16                       [+ legacy stats, ignored]
REGISTER_EX       (c→s, 0xE3)   hash:16  version:1
REGISTER ack v4   (s→c, 0xE4)   port:2 BE  ipv4:4 BE                              (6 B)
REGISTER ack v6   (s→c, 0xEC)   port:2 BE  ipv6:16                               (18 B)
SYNC2             (c→s, 0xE9)   srcHash:16  connAck:4  dstHash:16                (36 B)
SYNC v4           (s→c, 0xE1)   peerIPv4:4 BE  peerPort:2 BE  peerHash:16  connAck:4       (26 B)
SYNC_EX v4        (s→c, 0xE7)   ( SYNC v4 )  peerVersion:1                       (27 B)
SYNC_IPV6         (s→c, 0xED)   peerIPv6:16  peerPort:2 BE  peerHash:16  connAck:4  peerVersion:1  (39 B)
FAILED            (s→c, 0xE5)   reason:1  targetHash:16                          (17 B)
KEEPALIVE         (c→s, 0xE6)   (empty)          |  or a bare 1-byte datagram
PING              (s→c, 0xE2)   (empty)
```

- The register ack's `ipv4`/`ipv6` is the **server's own** public endpoint; the port
  is the UDP port the client should keep talking to. A client distinguishes the v4
  ack (6 B, opcode `0xE4`) from a register request by direction and length; the v6
  ack has its own opcode `0xEC`. An **all-zero** ack address means the server has no
  public address of that family to announce — keep using the address you dialed.
- `SYNC_IPV6` always carries `peerVersion` (0 if the peer registered without one);
  there is no separate EX form for v6.
- `FAILED` reason codes: `0x01` = target hash not registered; `0x02` = the two peers
  share no address family (e.g. a v4-only peer and a v6-only peer — they cannot
  punch); `0x03` = rendezvous restricted — the server has server-independent rendezvous
  turned off and one of the two peers is not logged into it (see *Cross-server /
  serverless rendezvous* below).

### Dual-stack candidate model

The server stores, **per user hash, up to two candidates** — one IPv4 and one IPv6 —
each being the source endpoint the server *observed* a register arrive from (it never
trusts a client-supplied address; NAT rewrites the source, and only the server sees
the translated public `ip:port`). A dual-stack client therefore **registers once per
family**: send `OP_NAT_REGISTER` from your IPv4 socket *and* from your IPv6 socket,
each carrying the same user hash. Each keeps its own freshness (TTL, default 30 s), so
keepalive on every family you registered.

At `SYNC2` time the server picks a **common family, preferring IPv6**: v6 if both
peers have a v6 candidate, else v4 if both have v4, else `FAILED 0x02`. So register
every family you can offer before `SYNC2`; at minimum register on the family of the
target source (which you already know from the source record).

### Sequence

```
target T                         server                        initiator I
  --OP_NAT_REGISTER(hashT)------->  store T.<fam>=src ; ack
  <-------------- REGISTER ack ----
  --OP_NAT_KEEPALIVE------------->  refresh ; <--- OP_NAT_PING
                                                   <--OP_NAT_REGISTER(hashI)--
                                                   store I.<fam>=src ; ack --->
                                                   <--OP_NAT_SYNC2(hashI,connAck,hashT)--
  <-- SYNC/ SYNC_IPV6(peer=I) ----  pick family ; relay ---> SYNC/ SYNC_IPV6(peer=T)
  ============ direct UDP punch between T and I (both mappings now open) ============
```

The **punch payload itself is not part of `PR_NAT`** — once each side has the peer's
endpoint it opens its own eD2K connection to it. (The reference simulator
`internal/natsim` sends `"PING"`/`"PONG"` there purely to prove reachability.)

### Cross-server / serverless rendezvous

The registry above is keyed by **user hash**, not by eD2K login: registering and
pairing are independent of whether the two peers are logged into this server, a
different server, or no server at all. This is what lets `PR_NAT` reach LowID↔LowID
pairs that the classic same-server callback cannot — the two peers on **different
servers or none** rendezvous through a common server that runs `PR_NAT`.

**How a client uses it (client side — the discovery half):**

1. **Detect** a rendezvous-capable server: `SRV_TCPFLG_NAT_RENDEZVOUS (0x8000)` in its
   flags word, and read `ST_NAT_PORT (0x9D)` from `OP_SERVERIDENT` for the UDP port
   (fall back to `2004` if absent). This may be a server you are logged into, or any
   public server you choose as your rendezvous **R**.
2. A firewalled target **T** registers with **R** (`OP_NAT_REGISTER`, keepalive) and
   learns **R**'s public endpoint from the REGISTER ack. T then **publishes** the pair
   `(its user hash, R's ip:port)` to its peers — via Kad or source-exchange, the same
   channel that carries any other contact info. eNode-go does **not** propagate this;
   carrying and reading it is the client's responsibility.
3. An initiator **I** that has learned `(hashT, R)` for a source sends
   `OP_NAT_SYNC2(hashI, connAck, hashT)` to **R** (SYNC2 auto-registers I's endpoint,
   so a prior REGISTER is optional). R pairs them exactly as in the sequence above and
   both punch — regardless of which servers I and T use for file discovery.

This is orthogonal to and independent of the eMuleAI **eServer buddy** relay
(`OP_ESERVER_* 0xB3–0xBB`), which is a client-to-client, **same-server**, IPv4-only
mechanism the eD2K server takes no part in. `PR_NAT` is the server-mediated path that
spans servers and covers IPv6.

**Gate.** `natTraversal.serverIndependent` (default **true**) controls this. When on,
the server pairs any two registered hashes and advertises the flag + `ST_NAT_PORT`.
When off, it drops both advertisements and refuses a `SYNC2` unless **both** hashes are
currently logged into it, replying `OP_NAT_FAILED` reason `0x03`; same-server
LowID↔LowID still works. The gate is family-agnostic — it applies equally to IPv4 and
IPv6 pairings, before family selection.

### Configuration

- `natTraversal.enabled` — run the service at all.
- `natTraversal.port` — its UDP port (default `2004`). The handler is also reachable
  on the main UDP port.
- `natTraversal.ipv6` — dual-stack hole-punching (default **true**). Effective only
  when `ipv6.enabled` is also on. When off, the server **declines** IPv6 `PR_NAT`
  datagrams (drops them, no ack, nothing stored) and the protocol is IPv4-only.
- `natTraversal.serverIndependent` — cross-server / serverless rendezvous (default
  **true**). When off, pairing is restricted to clients logged into this server
  (`OP_NAT_FAILED` reason `0x03` otherwise) and the capability flag + `ST_NAT_PORT` tag
  are not advertised.
