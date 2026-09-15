# Server-UDP obfuscation: the crypt-ping bootstrap

eNode-go answers the eMule **server-UDP crypt-ping** — the handshake a client uses to discover a
server's UDP obfuscation key before it holds one. This lets a crypt-capable client reach obfuscated
UDP immediately instead of stalling ~20 s and falling back to a plaintext stat exchange first.

Reference behaviour throughout is the official eMule tree at `eMuleQt/srchybrid`
(`EncryptedDatagramSocket.cpp`, `UDPSocket.cpp`, `ServerList.cpp`).

## How obfuscation is keyed

Server UDP traffic (stat pings, global search, global getsources) may be RC4-obfuscated. The key is
`MD5(baseKey[4] ‖ directionMagic[1] ‖ randomKeyPart[2])`, where:

- `baseKey` is the server's UDP key for this client — **per-client**, derived from the client's IP
  (see [Per-client keying](#per-client-keying-anti-spoofing) below);
- `randomKeyPart` is a fresh 16-bit value carried in the clear on every datagram, so the keystream
  differs per packet (the anti-DPI property — obfuscation here is **not** a security boundary);
- `directionMagic` differs per direction: `0x6B` (`MAGICVALUE_UDP_CLIENTSERVER`) client→server,
  `0xA5` (`MAGICVALUE_UDP_SERVERCLIENT`) server→client.

The `0x13EF24D5` `SYNC_SERVER` marker is the "did it decrypt?" check in both directions. The
server-UDP path skips the RC4-drop[1024] step (unlike the TCP handshake). eNode-go's crypto matches
this exactly (`ed2k/udpcrypt.go`).

## The bootstrap

Before a client holds `baseKey` it can't obfuscate anything, so it bootstraps
(`srchybrid/ServerList.cpp:273-294`, `UDPSocket.cpp:159-181,321-407`):

1. **Client → `tcp.port + 12`:** a **raw, unencrypted** 32-bit `challenge` (nonzero) plus up to 15
   random padding bytes. This is *not* an ed2k packet — just the challenge in little-endian followed
   by noise.
2. **Server → client:** `OP_GLOBSERVSTATRES`, encrypted with `baseKey = challenge` (direction magic
   `0xA5`), carrying the real `udp.serverKey` at offset **+36**.
3. The client decrypts with `baseKey = challenge` (it had set `cryptPingReplyPending`), stores
   `serverKey`, and uses it for every obfuscated datagram afterward.
4. If no reply arrives within 20 s, the client falls back to the plaintext stat on `tcp.port + 4`.

### Reply layout (`OP_GLOBSERVSTATRES`, 40-byte body)

| Offset | Field | eNode-go source |
|---|---|---|
| +0 | `challenge` (echoed) | `BuildGlobServStatResPacket`, `ed2k/udpoperations.go` |
| +4 | current users (+2000) | |
| +8 | current files | |
| +12 | max users | |
| +16 | soft file limit | `files.softLimit`, default 10000 — see [`server-client-communication.md`](server-client-communication.md#per-client-publish-limits) |
| +20 | hard file limit | `files.hardLimit`, default 20000 |
| +24 | UDP flags | |
| +28 | low-ID users (+1000) | |
| +32 | UDP obf port (uint16) | |
| +34 | TCP obf port (uint16) | |
| +36 | **per-client UDP key** (uint32) | `deriveUDPKey(udp.serverKey, clientIP)` — the key the client adopts |

## Why the obfuscated UDP port must be `tcp.port + 12`

The client **hardwires** the crypt-ping to `tcp.port + 12` (`ServerList.cpp:294`). Critically, on
first contact it can only associate the *reply* with the server when the reply's source port is
`tcp.port + 12` — `GetServerByIPUDP` matches `GetPort()+4` (plaintext), `GetObfuscationPortUDP()`
(still 0 before any stat), or `GetPort()+12` (`ServerList.cpp:563-576`). A reply from any other port
is unmatchable and dropped.

So eNode-go's obfuscated UDP listener must bind `tcp.port + 12`:

- Plaintext UDP stays at `tcp.port + 4` (5559) — already the port eMule pings for the unencrypted
  stat (`UDPSocket.cpp:771-772`).
- Obfuscated UDP defaults to `tcp.port + 12` (5567). `config.setDefaults` computes this; an explicit
  `udp.portObfuscated` in YAML still wins, but a value other than `tcp.port + 12` leaves the
  crypt-ping unreachable (clients degrade to the plaintext fallback — still functional, just
  slower).

Steady-state obfuscated UDP also runs on this port: the server advertises it at reply offset +32 and
clients honour the advertised value thereafter.

## Per-client keying (anti-spoofing)

The `+36` key is **not** the raw `udp.serverKey`. Each client gets its own key bound to its IP:

```
udpKey = deriveUDPKey(secret, clientIP) = uint32(MD5(secret ‖ clientIP)[:4])   // never 0
```

where `secret` is the configured `udp.serverKey` (now a server-wide seed, not the value sent
verbatim) and `clientIP` is the datagram's source IP (`ed2k/udpcrypt.go`). This restores the
handshake's anti-spoofing property that a single global key gave up: the key handed to one client no
longer lets a *different* host obfuscate as it.

The derivation is deterministic and keyed on IP only (not port), so:

- The server recomputes each client's key from the packet's source IP on every datagram — **no
  per-client state** is stored; the same key is used to decrypt the client's traffic and to encrypt
  replies to it.
- Both listeners advertise the *same* key for a given client: the obfuscated crypt-ping reply and
  the plaintext-fallback stat reply (`tcp.port + 4`) both carry `deriveUDPKey(secret, clientIP)` at
  `+36`, so a client that learned the key the slow way still obfuscates with a key the obfuscated
  listener reproduces.

eMule mirrors this on its side: it stores the key together with its own public IP and discards it
(re-pinging for a fresh one) the moment its public IP changes —
`CServer::GetServerKeyUDP()` returns `0` when `theApp.GetPublicIP()` no longer matches the IP
recorded at `SetServerKeyUDP()` time (`srchybrid/Server.cpp:279-291`). A NAT port change alone does
not invalidate the key, which is why the derivation excludes the port.

**Migration note.** The `+36` value changed from the raw `udp.serverKey` to a per-IP derivation.
A client that cached the old global key keeps using it until it re-pings (server reconnect, its
public IP changes, or app restart), after which it adopts the per-client key. Rotating `udp.serverKey`
has the identical effect and always did — it is server key material, not a stable client-visible id.

## Server-side handling (`ed2k/server_runtime.go`)

On the obfuscated listener only, a datagram that fails per-client-key decryption (no `SYNC_SERVER`,
so its first byte is not `PR_ED2K`) and is 4–19 bytes long is treated as a crypt-ping: the first 4
bytes are the challenge, and the server replies with the stat res encrypted keyed on that challenge
(`udpCryptPingReply`), carrying `deriveUDPKey(secret, clientIP)` at `+36`. A zero challenge is
ignored (eMule never sends one). The per-datagram crypt is built from the source IP inside the
handler because datagrams are dispatched concurrently across a worker pool (`ed2k/udpserver.go`).

Length is the only available signal — the challenge is unframed random bytes — but a false positive
costs a single stat-reply datagram, on par with the plaintext `OP_GLOBSERVSTATREQ` this server
already answers unthrottled (≈48 bytes out for ≥4 in), so it adds no new reflection/amplification
exposure. Two negligible edges: a challenge whose low byte is `0xE3` (~1/256) is read as a plaintext
`PR_ED2K` packet and goes unanswered, and one whose first byte is `0xF1` (`PR_NAT`) is routed to the
NAT handler — in both cases the client simply re-pings on its next cycle.

## Out of scope / by design

- **Client-side receive bug.** A separate defect in eMuleQt's `decryptReceivedServer` (using `0x6B`
  where the protocol requires `0xA5`) prevents it from decrypting *any* correct server's obfuscated
  reply; it is tracked and fixed in the eMuleQt tree, not here.
