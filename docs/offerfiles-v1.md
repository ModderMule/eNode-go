# OFFERFILES v1: server-paced fast publishing

eNode-go implements OFFERFILES v1 with the same contract as
[ed2k-server](https://github.com/andrey23127/ed2k-server#offerfiles-v1-fast-publishing)
and aMule's client (`docs/ED2K_EXTENSIONS.md` in aMule master). Requested in
[emule-qt#185](https://github.com/ModderMule/emule-qt/issues/185).

## Why

A stock eMule or aMule client publishes at most 200 files per `OP_OFFERFILES` and
sends one packet a minute. It does this because a Lugdunum server may black out an
IP that publishes faster, and a client cannot tell this server from one of those. At
that pace a 10,000-file share takes 50 minutes to publish and a 60,000-file share
takes 5 hours. v1 lets the server tell the client a faster pace. At the defaults
(200 files every 500 ms) 10,000 files take about 25 seconds.

## Wire contract

1. **The client asks.** `OP_LOGINREQUEST` carries the string-named `uint32` tag
   `offerfiles_v` with the highest version the client implements (1). The tag is
   old format: type `0x03`, `uint16` name length, name, `uint32` value. The server
   treats every other shape (tag absent, another type, value 0) as a legacy client.
   A server that does not know the tag skips it.
2. **The server answers only a client that asked.** The answer goes in the
   `OP_SERVERIDENT` sent right after login and nowhere else. It is not repeated
   in the answer to `OP_GETSERVERLIST`. Each tag appears exactly once, and all are
   `uint32`:

   | Tag | Name kind | Meaning |
   |---|---|---|
   | `ST_SOFTFILES` (0x88) | numeric | distinct files the connection may have indexed (`files.softLimit`) |
   | `ST_HARDFILES` (0x89) | numeric | every packet must declare fewer records than this (`files.hardLimit`) |
   | `offerfiles_v` | string | `1` |
   | `offerfiles_batch_max` | string | most records in one `OP_OFFERFILES` |
   | `offerfiles_min_interval_ms` | string | least time between two packets |

   The advertisement is all or nothing. It needs soft > 0, batch_max > 0,
   interval > 0 and hard > batch_max. When one fails (in eNode-go, typically a file
   limit set to 0, meaning unlimited), no `offerfiles_*` tag is sent, a warning is
   logged, and the client is treated as legacy.
3. **On a v1 connection**, each `OP_OFFERFILES` is checked in this order:
   - It declares `ST_HARDFILES` records or more: the packet is refused and the
     connection closed, as for any client.
   - It declares more than `offerfiles_batch_max` records: the packet is not indexed,
     and the session stays up. The packet is counted in the admin Blocks tab.
   - It arrives before it is due: it waits until it is due and is never dropped.
   - Otherwise it goes through the content filter, the soft limit and indexing, as
     for a legacy client.

The five values are a snapshot taken at login and kept in `tcpClient.offerV1`.
Every limit applied to a v1 connection comes from that snapshot, so the server
enforces exactly what it advertised. A config reload reaches new logins only. A
legacy client is never held to any of the v1 rules.

## Pacing

A per-connection token bucket counts file records. It holds one batch, starts full
(so the first batch is processed at once) and refills at `batchMax` records per
`minIntervalMs`. A smaller batch costs proportionally less. When two frames arrive
together over TCP, the second is not an offence; it is processed when it is due. The
connection's own goroutine does the waiting and reads nothing more meanwhile, so TCP
backpressure holds the client back instead of a queue in the server. A wait is cut
short when the session is closing or a handover starts parking sessions, because the
batch has already been read off the stream.

The policy moves with the session across a handover (`SessionState.OfferV1`). The
bucket does not: the successor starts it full.

ed2k-server also has a server-wide ceiling shared by every v1 connection
(`offerfiles_global_records_per_sec`). It is not part of the client contract and is
not implemented here (see the ToDo in `ed2k/offerfiles_v1.go`).

## Configuration

```yaml
files:
  softLimit: 10000
  hardLimit: 20000
  offerFilesV1:
    enabled: true      # only clients that ask are affected
    batchMax: 200      # must be below hardLimit
    minIntervalMs: 500 # 1-60000
```

## Code

- `ed2k/offerfiles_v1.go`: the login check, policy, advertisement and bucket.
- `ed2k/server_runtime.go`: `handleLoginRequest`, `handShake` (sends the
  advertisement) and `handleOfferFiles` (enforcement).
- `ed2k/buffer.go`: `Tag.Name`, for string-named tags on the wire.
- Tests: `ed2k/offerfiles_v1_test.go`, `config/offerfiles_v1_config_test.go`.
