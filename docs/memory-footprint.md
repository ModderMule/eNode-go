# Memory footprint

How much RAM an eNode-go server uses, per file and per online user, and what that
works out to at the scale of the servers currently on the eD2K network.

Everything marked **measured** was taken from a real `ServerRuntime` process — the
production TCP listener, the production `MemoryEngine`, real loopback sockets driven
from a second process — not from `unsafe.Sizeof` arithmetic. Where a figure is
arithmetic or an assumption, it says so.

Measurement environment: Go 1.25.3, `darwin/arm64`, default `GOGC`, no `GOMEMLIMIT`,
2026-07-30.

---

## 1. Rules of thumb

| Quantity | Cost |
|---|---|
| One distinct file (1 source, ~60-char name) | **~560 B** live heap |
| Each additional source of a file | **~130 B** |
| One logged-in session (socket + goroutines + state) | **~16 KiB** RSS |
| Idle server, nothing connected | **12 MiB** RSS |

Which collapses to: **~0.6 GB per million files, ~160 MB per 10,000 online users**,
plus 50% headroom for the garbage collector (§6).

The file cost applies to the `memory` storage engine only. With `mysql` or
`mongodb` the index lives in the database and the Go process pays only the session
cost — see §7.

For what those unit costs come to at one concrete server size — and for the per-client
`softLimit` that decides how large the index gets in the first place — see §4, and
[`file-publish-limits.md`](file-publish-limits.md) for how that cap is configured and
enforced.

---

## 2. Measured unit costs

### 2.1 Files — `MemoryEngine`

Raw process samples, memory engine preloaded with N files, one source each,
`The.Great.Release.%08d.S01E04.1080p.WEB-DL.x264-GROUP.mkv` names (62 chars), no
audio/video metadata tags:

| Files | Live heap | Heap sys | RSS | Live bytes/file |
|---:|---:|---:|---:|---:|
| 0 | 0.6 MiB | 3.8 MiB | 11.8 MiB | — |
| 1,000,000 | 518.7 MiB | 599.2 MiB | 621.6 MiB | **544 B** |
| 5,000,000 | 2708.9 MiB | 2739.2 MiB | 2814.6 MiB | **568 B** |

The per-file cost is not perfectly flat because Go maps double their bucket arrays:
where you land in that cycle moves the figure between roughly 540 and 600 B. **560 B
is the planning number.**

A tighter in-package measurement (200k files, heap delta around a fresh engine) isolates
the variables:

| Shape | Bytes/file |
|---|---:|
| 200k files, 59-char names, 1 source | 450 B |
| 200k files, 94-char names, 1 source | 482 B |
| 200k files, 59-char names, 3 sources | 690 B |
| 200k files, 59-char names, 10 sources | 1794 B |

So: **+32 B per 35 characters of filename**, and **~120–150 B per extra source** (the
spread is slice-growth slack — `m.sources[k]` doubles its capacity, so a file with 10
sources carries 6 unused 72-byte slots).

The whole-process figure runs ~100 B/file above the in-package one because the process
carries the map-growth headroom of a much larger table, slightly longer names, and a
distinct 16-byte user hash allocation per source record.

### 2.2 Where the bytes go

Struct sizes are exact (`unsafe.Sizeof`); the rest is the allocator's rounding and Go's
map overhead:

| Component | Bytes |
|---|---:|
| `storage.File` value in `m.files` | 152 |
| `Name` string data (60 chars → 64-byte size class) | 64 |
| `File.Hash` backing array | 16 |
| `m.files` key string data (the 16-byte hash) | 16 |
| `m.sources` key string data | 16 |
| `[]Source` header + 1-element backing array (`Source` = 72 B) | 96 |
| `Source.UserHash` backing array | 16 |
| Go map bucket/control overhead across two maps | ~180 |
| **Total** | **~560** |

Two maps are keyed by the same 16-byte hash (`files` and `sources`), which is where a
surprising amount of it goes: about a third of the per-file cost is map machinery and
duplicated keys rather than payload.

Audio/video metadata (`Title`, `Artist`, `Album`, `Codec`) costs the length of those
strings plus allocator rounding when a client supplies them — order 100 B/file. *Not
measured*; the samples above were built without metadata tags.

### 2.3 Sessions

Measured with 10,000 real TCP sessions, each logged in with a distinct user hash from a
separate driver process, so the numbers below are the server side only:

| State | Goroutines | Live heap | Stacks | RSS |
|---|---:|---:|---:|---:|
| Idle | 2 | 0.6 MiB | 0.2 MiB | 11.9 MiB |
| 10,000 logged in | 20,002 | 74.6 MiB | 66.4 MiB | 166.0 MiB |

**154 MiB for 10,000 sessions → ~15.8 KiB per session**, split roughly:

- **6.8 KiB of goroutine stack.** Two goroutines per client: the read loop
  (`tcpClient.run`) and the periodic status ticker. ~3.4 KiB each after growth from
  Go's 2 KiB minimum.
- **4 KiB read buffer** — `buf := make([]byte, 4096)` in `tcpClient.run`, one per
  connection for the life of the session.
- **~3.4 KiB** of `tcpClient`, `Packet`, `net.TCPConn`/`netFD`/pollDesc, the
  `sessionsByHash` and `LowIDs` entries, and the engine's client record.
- The engine's client record on its own is **214 B** (measured: 200k `Connect` calls,
  `ClientInfo` = 96 B plus hash and two map entries) — i.e. 1.3% of a session. Almost
  all of the per-user cost is the connection, not the bookkeeping.

---

## 3. If the live network ran eNode-go

Source: `eMuleQt/data/config/server.met`, ten servers, user and file counts as each
advertises them (2024 snapshot). Assumes **1.2 sources per distinct file** — plausible
for eD2K, where most files have one source and a small popular tail has many. The index
column scales linearly in that assumption: 1.0 → −5%, 2.0 → +33%.

| Server | Users | Files | Index | Sessions | Total |
|---|---:|---:|---:|---:|---:|
| eMule Sunrise | 46,516 | 27,397,581 | 15.0 GiB | 727 MiB | **15.7 GiB** |
| eMule Security | 24,361 | 12,181,708 | 6.6 GiB | 381 MiB | **7.0 GiB** |
| !! Sharing-Devils No.2 !! | 6,405 | 3,385,106 | 1.8 GiB | 100 MiB | **1.9 GiB** |
| !! Sharing-Devils No.1 !! | 5,791 | 2,890,296 | 1.6 GiB | 91 MiB | **1.7 GiB** |
| GrupoTS Server | 5,210 | 2,179,848 | 1.2 GiB | 81 MiB | **1.3 GiB** |
| !! Sharing-Devils No.3 !! | 4,166 | 1,827,294 | 997 MiB | 65 MiB | **1.1 GiB** |
| Astra-3 | 3,635 | 1,687,637 | 943 MiB | 57 MiB | **1000 MiB** |
| Akteon Server | 2,930 | 1,158,962 | 648 MiB | 46 MiB | **694 MiB** |
| Astra-5 | 2,205 | 1,053,791 | 589 MiB | 35 MiB | **623 MiB** |
| Akteon Server No2 | 1,371 | 828,206 | 463 MiB | 21 MiB | **484 MiB** |
| **All ten combined** | **102,590** | **54,590,429** | **29.8 GiB** | **1.6 GiB** | **31.4 GiB** |

Two observations worth keeping in mind:

- **The index dominates by 20:1.** Users are cheap; files are not. Sunrise's 46k
  concurrent users cost less RAM than 1.3M of its 27.4M files.
- **The whole public network fits in one machine.** All ten servers' indices together
  are 31 GiB — a single 64 GB host could hold the entire advertised eD2K index with the
  memory engine.

---

## 4. A 44,000-user server, and what `softLimit` has to do with it

### 4.1 The soft and hard file limits are per-client publish caps

Not server capacity figures — which matters here, because the number that drives RAM is
the sum of what every client publishes, and the soft limit is the only lever the protocol
gives a server over it.

- **Definition.** Lugdunum's own documentation, vendored at
  [`lugdunum-eserver/docs/kiten-20071012.txt:462`](../lugdunum-eserver/docs/kiten-20071012.txt):
  *"softLimit: If a client tries to publish more than softLimit files, the server sends him
  a WARNING message and ignores files in excess. Default value: 1000"*, and at `:349`
  *"hardLimit: If a client tries to publish more than hardLimit files, the server
  disconnects him (before receiving the whole list)… Default value: 4000"*. eserver reports
  both in its live stats line (`lugdunum-eserver/docs/eserver-17.14-strings.txt:20339`,
  `…:softLimit=%u:hardLimit=%u:…`).
- **On the wire.** Offsets +16 and +20 of `OP_GLOBSERVSTATRES`
  (layout comment at `ed2k/gossipoperations.go:311`, parsed into
  `StatResFields.SoftFiles/HardFiles` at `:288-289`),
  and persisted per server in `server.met` as `ST_SOFTFILES 0x88` / `ST_HARDFILES 0x89`
  (`eMuleQt/src/core/utils/Opcodes.h:371`, `src/core/server/Server.cpp:209`).
- **What the client does with it.** `eMuleQt/src/core/files/SharedFileList.cpp:639`:
  `limit = srv->softFiles();` then `if (limit == 0 || limit > kMaxOfferedFiles) limit = 200;`
  — mirroring `srchybrid/SharedFileList.cpp:832-834`. So one `OP_OFFERFILES` never carries
  more than 200 files and the server's soft limit can only lower that; the client
  republishes the remainder every 60 s (`kEd2kRepublishSecs`) until its whole share is
  registered. The soft limit therefore bounds a client's **cumulative** share on the
  server, not the size of one packet.
- **What eNode-go does with it.** Both limits are configured under `files:` — `softLimit`
  defaulting to 10000, `hardLimit` to 20000, the values that used to be hardcoded in
  `BuildGlobServStatResPacket` — and both are now enforced. `handleOfferFiles`
  (`ed2k/server_runtime.go`) counts the records each session publishes, ignores everything
  past the soft limit after one `WARNING` message, and disconnects past the hard one. The
  advertised numbers and the enforced numbers come from the same two config keys, so a
  client is never told one thing and held to another. The count is cumulative across the
  session's packets, which is the only way either cap can bite given the 200-file packet
  ceiling above; it counts records rather than distinct hashes, which is the same number
  for a conforming client. See [`file-publish-limits.md`](file-publish-limits.md).

  This is what makes the middle row below a real ceiling rather than a projection. The
  third row now takes a deliberate act — raising `files.softLimit` — rather than merely a
  client that felt like it.

### 4.2 Scenarios at 44,000 online users

Arithmetic from the measured unit costs in §2 — 560 B per distinct file, 130 B per extra
source, 15.8 KiB per session, 12 MiB base — assuming **1.2 sources per distinct file**, the
same dedup assumption as §3.

The unit costs were re-measured for this section on 2026-09-13 under Go 1.27.0,
`darwin/arm64` (the §2 figures are Go 1.25.3), in-package, heap delta around a fresh
`MemoryEngine`: 300k files with 62-char names and one source each came to **483 B/file**, a
second source on 20% of them added **80 B per extra source** (499 B/file overall at 1.2
sources), and 44,000 `Connect()` calls cost **239 B per client record**. All within the
map-growth spread of §2.1, so the planning numbers stand.

Sessions are noise at this scale: 44,000 × 15.8 KiB = **0.66 GiB** regardless of the index.

| Files published per user | Offer records | Distinct files | Index | Total live | Provision (×1.5) |
|---|---:|---:|---:|---:|---:|
| **589** — the network average¹ | 25.9 M | 21.6 M | 11.8 GiB | 12.5 GiB | **~19 GiB** |
| **10,000** — every user at the default soft limit | 440 M | 366.7 M | 200.1 GiB | 200.8 GiB | **~300 GiB** |
| **100,000** — every user at a raised `files.softLimit` | 4.4 B | 3.67 B | 2001 GiB | 2002 GiB | **~3 TiB** |

¹ 27,397,581 files / 46,516 users, from eMule Sunrise in the §3 table — the largest server
on the public network, and the closest thing to a measured files-per-user figure we have.

Dedup sensitivity, as in §3: 1.0 source per file → +15%, 2.0 → −30%.

Inverted, the same model says what a given box holds with 44,000 users connected:

| Host RAM | Distinct files | Sustainable files published per user |
|---:|---:|---:|
| 16 GB | 18.3 M | ~500 |
| 32 GB | 37.9 M | ~1,030 |
| 64 GB | 76.9 M | ~2,100 |
| 128 GB | 155 M | ~4,230 |
| 256 GB | 311 M | ~8,500 |

### 4.3 Reading those tables

- **Only the first row is a real machine.** 44k users sharing at eD2K-typical rates is
  ~19 GiB provisioned — comfortable on a 32 GB host with `GOMEMLIMIT` set (§6). If every
  user filled the default `files.softLimit` of 10,000, the same server is a 300 GiB working
  set, and a `softLimit` raised to 100,000 is 3 TiB. Those are the DB engines' territory
  (§7), where the same 44k sessions cost ~0.7 GiB of Go process.
- **RAM is not the wall that arrives first.** `MemoryEngine.FindBySearch`
  (`storage/storage.go:280-296`) is a full map scan under `RLock`; at 366 M entries every
  search walks the whole table before the `MaxSearchResults` cap can stop it. That is the
  §8 caveat restated at this scale: the index becomes a CPU and lock-hold problem an order
  of magnitude before it becomes a memory problem.
- **`pendingResults` scales with users, not files.** 44,000 sessions each pinning a
  1000-file search tail is ~8.6 GiB on top of the index (§8), and it is the one per-session
  cost that is not a flat 16 KiB.
- **Two costs that sit outside the heap**: ~44k × 4–10 KiB of kernel socket buffers
  (180–440 MB), and the snapshot file at ~120 MB per million files compressed — 2.6 GB for
  the first row, 44 GB for the second, written by walking the whole index in 10,000-file
  batches (`storage/snapshot.go:68-73`).

---

## 5. Reproducing this

The probe was a scratch program, deliberately not kept in the tree. To rebuild it:

```go
// zz_memprobe/main.go — mode=server runs the real runtime and prints its own
// stats each second; mode=client opens -n real sockets and logs each one in.
rt := ed2k.NewServerRuntime(ed2k.TCPRuntimeConfig{
    Address: "127.0.0.1", Port: 14661, Hash: bytes.Repeat([]byte{0x11}, 16),
    AllowLowIDs: true, ConnectionTimeout: 2 * time.Second,
    ServerStatusInterval: time.Hour, // keep the tickers quiet during measurement
}, ed2k.UDPRuntimeConfig{}, storage.NewMemoryEngine())
ln, _ := ed2k.RunTCPServer(ed2k.TCPServerConfig{
    Address: "127.0.0.1", Port: 14661, MaxConnections: 0,
}, rt.TCPHandler(false))
// then loop: runtime.ReadMemStats + ps -o rss= -p <pid>
```

Four things the harness has to get right, each of which silently ruins the number:

- **Drive the clients from a second process.** Both ends in one process double-counts
  every socket and goroutine.
- **Unique user hash per client.** `handleLoginRequest` rejects a duplicate hash
  outright (`server_runtime.go:793`), so 10,000 clients sharing one hash measures one
  session and 9,999 rejections.
- **Dial-back must fail fast.** Clients advertise a loopback port nothing listens on, so
  `probeFirewalled` gets an instant refusal and assigns a LowID. A routable-but-dead
  address would make every login block for the probe timeout.
- **`runtime.GC()` twice before reading `HeapAlloc`**, and set
  `logging.SetLevel(logging.LevelError)` — per-session log lines otherwise allocate more
  than the sessions do.

For the engine-only figures the equivalent is a `storage` package test that snapshots
`HeapAlloc` around a fresh `MemoryEngine`, with **unique** strings per file: shared
string constants share one backing array and understate metadata cost to zero.

---

## 6. Provisioning

The figures above are *live heap*. With the default `GOGC=100` the heap is allowed to
double before a collection runs, so under steady-state churn (logins, offers, cleanup)
RSS can approach 2× live. The preload samples in §2.1 show only 1.01–1.15× because they
build monotonically and generate almost no garbage — do not plan from those.

- Provision **~1.5× the table in §3**, and set **`GOMEMLIMIT`** to the box's usable
  memory so the collector tightens up instead of the OOM killer arriving. For Sunrise
  that means a 24–32 GB host; for the mid-tier servers 3–4 GB; for Akteon No2 under 1 GB.
- **Kernel socket buffers are not in RSS.** On Linux budget another ~4–10 KiB per idle
  TCP connection outside the process — for 46k users that is another ~250 MB of kernel
  memory, and `net.core.rmem_default`/`wmem_default` control it.
- **On-disk cost tracks these figures.** With `storage.snapshot.enabled` the index is
  also written to a gob file, at roughly 120 MB per million files compressed and 250 MB
  uncompressed — below the RAM numbers here, because the file carries the payload
  without map overhead, allocator rounding or the duplicated hash keys. See
  [`docs/storage-snapshot.md`](storage-snapshot.md).
- `cleanup` (see `storage.CleanupStale`) is what keeps the index from growing without
  bound. With `keepZeroSourceFiles` on, files whose last source left stay resident
  forever — that is a policy choice with a directly measurable RAM price of 560 B per
  retained file.

---

## 7. Database engines

With `storage.engine: mysql` or `mongodb` the file index is not in the Go process at
all. The process then costs:

- 12 MiB base,
- ~16 KiB per online session (identical — it is the connection, not the engine),
- plus the transient working set of in-flight searches.

So eMule Sunrise's 46,516 users would be **~730 MiB of Go process**, and the 15 GiB of
index becomes the database's problem, where it is paged rather than resident. That is
the trade: RAM for query latency.

---

## 8. Caveats

- **`pendingResults` pins search tails.** A session that ran a search wider than one
  page holds up to `storage.MaxSearchResults` (1000) `File` values until it pages
  through them or issues another search — ~200 KB per session worst case. Bounded, but
  46k sessions all doing it at once is 9 GB. It is the one per-session cost that is not
  a flat 16 KiB.
- **`MaxWireSources` (255) caps the tail, not the storage.** The engine stores every
  source; only the reply is truncated. A file with 5,000 sources costs 5,000 records.
- **RAM is not the first wall on a large memory-engine index.** `FindBySearch` is a full
  map scan under `RLock`. At 27M files that is a CPU and lock-hold problem long before
  the 15 GiB is a problem — which is the actual argument for the SQL/Mongo engines at
  that scale, not memory.
