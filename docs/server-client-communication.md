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
| `OP_OFFERFILES` | `0x15` | Client -> Server | Submit shared file/source list. |
| `OP_GETSOURCES` | `0x19` | Client -> Server | Request sources for a file. |
| `OP_GETSOURCES_OBFU` | `0x23` | Client -> Server | Obfuscated source request variant. |
| `OP_SEARCHREQUEST` | `0x16` | Client -> Server | Search query request. |
| `OP_QUERY_MORE_RESULT` | `0x21` | Client -> Server | Next page of the last search. Empty payload — the client's "More" button sends only the opcode (`srchybrid/SearchResultsWnd.cpp:1282`), so the remaining results are held per connection. |
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
| `OP_GETSOURCES_IPV6` | `0x24` | Client -> Server | IPv6 tag-block source query (opt-in); payload as `OP_GETSOURCES2`. |
| `OP_FOUNDSOURCES_IPV6` | `0x25` | Server -> Client | IPv6 tag-block source response (per source: `id+port+tagCount+tags`). |
| `OP_CALLBACKREQUESTED_IPV6` | `0x26` | Server -> v6-capable client | IPv6 form of `OP_CALLBACKREQUESTED`; sent when the requester has no usable IPv4 but a reachable public IPv6. |

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

## UDP OP Codes

| OP constant | Hex | Direction | Meaning |
|---|---:|---|---|
| `OP_GLOBGETSOURCES` | `0x9a` | Client -> Server | UDP source query by hash. |
| `OP_GLOBGETSOURCES2` | `0x94` | Client -> Server | UDP source query with hash+size. |
| `OP_GLOBSERVSTATREQ` | `0x96` | Client -> Server | UDP server stats request. |
| `OP_SERVERDESCREQ` | `0xa2` | Client -> Server, and Server -> Server | UDP server description request. Also *sent* by us to a gossip peer as the admission probe, and its `0xa3` reply parsed — see [`server-gossip.md`](server-gossip.md). |
| `OP_GLOBSEARCHREQ` | `0x98` | Client -> Server | UDP search request. |
| `OP_GLOBSEARCHREQ3` | `0x90` | Client -> Server | Extended UDP search request (tree/tags). |
| `OP_GLOBFOUNDSOURCES` | `0x9b` | Server -> Client | UDP source response. |
| `OP_GLOBSERVSTATRES` | `0x97` | Server -> Client | UDP server stats response. |
| `OP_SERVERDESCRES` | `0xa3` | Server -> Client | UDP server description response. |
| `OP_GLOBSEARCHRES` | `0x99` | Server -> Client | UDP search results response. |
| `OP_GLOBGETSOURCES_IPV6` | `0xa5` | Client -> Server | IPv6 tag-block UDP source query (opt-in); payload as `OP_GLOBGETSOURCES2`. |
| `OP_GLOBFOUNDSOURCES_IPV6` | `0xa6` | Server -> Client | IPv6 tag-block UDP source response. |
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
LowID↔LowID — and advertise it via `SRV_TCPFLG_NAT_RENDEZVOUS (0x8000)` plus a
`ST_NAT_PORT (0x9d)` uint16 tag in `OP_SERVERIDENT`; when off, pairing is restricted to
clients logged into this server (`OP_NAT_FAILED` reason `0x03`). Full protocol + byte-exact
layouts: [`ipv6-client-implementation-spec.md`](ipv6-client-implementation-spec.md) §9.

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
| `OP_IDCHANGE` | Server -> Client | `clientID(uint32) + tcpFlags(uint32) + primaryTCPPort(uint32) + observedClientIPv4(uint32)`. eMule's full documented layout (`srchybrid/Opcodes.h:182`); it lower-bounds the size only, reading the flags at size >= 8 and the observed IP at size >= 16. `primaryTCPPort` is annotated "unused" by the reference and ignored by both surveyed clients. `observedClientIPv4` is the address the socket arrived from — the only public-IPv4 source a LowID client has — and is `0` when the server has no routable IPv4 for the session (v6-only, or a value a client would reject as a LowID). Such a session is assigned a LowID as well — an address ending in `.0` packs into the LowID range, so it cannot be a HighID either — which keeps `clientID` and `observedClientIPv4` consistent. See [`ipv6-client-implementation-spec.md`](ipv6-client-implementation-spec.md) §2 and §3a. |
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

Two consequences worth knowing when writing the text:

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
`udp.portObfuscated` (`tcp.port + 12`) and shares the same socket, so in practice the
advertised value is unchanged from a gossip-less server — `tcp.port + 14` was tried and
does not work, since Lugdunum reads a peer's TCP port as this value minus 12. See
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
- There is no server-to-server gossip: the `OP_SERVERLIST` we return is the static
  `servers:` list from config, and the UDP `SERVER_LIST_REQ/RES` (`0xa0`/`0xa1`)
  exchange other servers use to trade peers is not implemented.
- For how this surface compares to other server implementations — in particular
  which extensions are ours alone and which LowID↔LowID design belongs to whom —
  see [`ed2k-server-rust-comparison.local.md`](ed2k-server-rust-comparison.local.md).
