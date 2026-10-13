# Memory footprint

How much RAM an eNode-go server uses, per file and per online user, and what that
works out to at the scale of the servers currently on the eD2K network.

Everything marked **measured** was taken from a real `ServerRuntime` process — the
production TCP listener, the production `MemoryEngine`, real loopback sockets driven
from a second process — not from `unsafe.Sizeof` arithmetic. Where a figure is
arithmetic or an assumption, it says so.

Measurement environment: Go 1.25.3, `darwin/arm64`, default `GOGC`, no `GOMEMLIMIT`,
2026-07-30. The file and source costs were measured again on 2026-10-13, after the
memory engine's records were made compact (§2.2); the session costs are from the first
date.

---

## 1. Rules of thumb

| Quantity | Cost |
|---|---|
| One distinct file (1 source, ~60-char name), name index included | **~360 B** live heap |
| Each additional source of a file | **~55 B** |
| One logged-in session (socket + goroutines + state) | **~16 KiB** RSS |
| Idle server, nothing connected | **12 MiB** RSS |

Which collapses to: **~0.36 GB per million files, ~160 MB per 10,000 online users**,
plus 50% headroom for the garbage collector (§6).

Until 2026-10-13 a file cost ~560 B without the name index and ~730 B with it, and an
additional source ~130–275 B.

The file cost applies to the `memory` storage engine only. With `mysql` or
`mongodb` the index lives in the database and the Go process pays only the session
cost — see §7, and §7.1 for a full 50,000-user MariaDB server spec.

For what those unit costs come to at one concrete server size — and for the per-client
`softLimit` that decides how large the index gets in the first place — see §4, and
[`server-client-communication.md`](server-client-communication.md#per-client-publish-limits)
for how that cap is configured and enforced.

---

## 2. Measured unit costs

### 2.1 Files — `MemoryEngine`

In-package measurement, 2026-10-13: 200,000 files published through `Connect` and
`AddFile` into a fresh engine, heap delta after a forced GC. Names are
`The.Great.Release.%08d.S01E04.1080p.WEB-DL.x264-GROUP.mkv` (59 chars), each with a
number of its own, so the name index gains one word per file. "Before" is the same
measurement on the engine as it was until that day; both columns include the name
index.

| Shape | Before | Now |
|---|---:|---:|
| 59-char names, 1 source | 726 B | **358 B** |
| 94-char names, 1 source | 757 B | 390 B |
| 59-char names, 3 sources | 1187 B | 469 B |
| 59-char names, 10 sources | 3201 B | 842 B |
| 59-char names, 1 source, title + artist + codec + length + bitrate | 773 B | 502 B |
| 59-char names, 1 source, client with an IPv6 address | 741 B | 358 B |

So: **+32 B per 35 characters of filename**, and **~55 B per extra source** (a 24-byte
source record, the slack of a list that doubles as it grows, and for the second source
the entry that holds the list). An IPv6 address costs a file nothing: it is stored once
per session. Media tags cost the record that holds them (96 B) plus their strings.

On the `tests/membench` workload, whose names share words the way real file names do
more than these do, a file costs 313–330 B from 100,000 to 5 million files, and the
share of one large client 222 B a file (see
[`memory-engine-benchmark.md`](memory-engine-benchmark.md)).

Raw whole-process samples from 2026-07-30, before the name index and before the
compact records, kept for the method: memory engine preloaded with N files, one source
each, 62-char names, no audio/video metadata tags.

| Files | Live heap | Heap sys | RSS | Live bytes/file |
|---:|---:|---:|---:|---:|
| 0 | 0.6 MiB | 3.8 MiB | 11.8 MiB | — |
| 1,000,000 | 518.7 MiB | 599.2 MiB | 621.6 MiB | 544 B |
| 5,000,000 | 2708.9 MiB | 2739.2 MiB | 2814.6 MiB | 568 B |

The per-file cost is not perfectly flat because Go maps double their bucket arrays:
where you land in that cycle moves the figure by a few percent. The whole-process probe
has not been run again; the in-package figures above are the current ones.

### 2.2 Where the bytes go

One file with one source and a 59-char name. Struct sizes are exact (`unsafe.Sizeof`,
pinned by `TestMemoryRecordSizes`); the rest is the allocator's rounding and Go's map
overhead:

| Component | Bytes |
|---|---:|
| `memRec`, the file's record in the slab: name header, hash as `[16]byte`, size, the first source inline (24 B), a pointer to the media tags, the link to another size of the same hash, type and flags | 80 |
| Name string data (59 chars → 64-byte size class) | 64 |
| `files` map entry: 16-byte hash → 4-byte record id, with control bytes and growth slack | ~35 |
| The session's list of what it offered: one 4-byte record id | 4–8 |
| Name index: the words of the name, their posting entries and trigram lists | ~170 |
| **Total** | **~358** |

The name index share is this workload's: every name brings a word no other name has.
Where the words are already known it is the posting entries alone, about 4 B per word
of the name.

What a file no longer pays for, against the 726 B of the table above:

- **One map instead of two.** `files` was keyed by hash *and* size and `sources` by the
  hash, each with its own copy of the key as a string. Now `files` maps the bare hash
  to the first record with it, and a second size of the same hash, which is rare, hangs
  off that record. The size-less source query of legacy UDP is still one lookup.
- **No source list for one source.** The first source of a hash lives in the record.
  A second map, `more`, holds the lists of the files that have more.
- **24 B per source instead of 88 B plus two allocations.** A source keeps the ed2k id,
  the port, the size it offered, its crypt options and two flags, and a pointer to its
  session's identity. The user hash and the IPv6 address are stored once per session
  instead of being copied into every source.
- **Media tags behind a pointer.** `Title`, `Artist`, `Album`, `Codec`, `Runtime`,
  `Bitrate` and `Meta` took 96 B of every record. A file with none of them now pays 8.
  The type is one byte: it can only be one of six values.
- **4 B per offered file instead of ~40.** A session's offered files were a set keyed by
  the 16-byte hash. They are a list of record ids; whether a session already sources a
  file is read off the file's sources.
- **No stored counts.** `Sources`, `Completed` and the result source of a record were
  recomputed on every read already; they are no longer stored.

`storage.File` and `storage.Source` are what callers see and what the snapshot file
holds, unchanged. The layout above is private to the memory engine; the MySQL and
MongoDB engines are not affected.

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
- **No packet payload between packets.** A packet's payload is gathered in a buffer of
  its own (`Packet.recv`, sized by what arrives) and dropped once the packet has been
  handled (`Packet.release`). Until 2026-10-13 the session kept the last payload until
  the header of its next packet arrived: for a client that had just published, a
  200-file offer of about 16 KiB, for the rest of the minute or of the session. The
  figures in the table were taken with login packets only, so they do not show it.
- **~3.4 KiB** of `tcpClient`, `Packet`, `net.TCPConn`/`netFD`/pollDesc, the
  `sessionsByHash` and `LowIDs` entries, and the engine's client record.
- The engine's client record on its own is **307 B** (measured 2026-10-13: 44,000
  `Connect` calls; `ClientInfo` = 96 B, the identity its sources share, and two map
  entries) — i.e. 2% of a session. Almost all of the per-user cost is the connection,
  not the bookkeeping. On top of it a session's list of offered files costs 4–8 B per
  file.

### 2.4 Against the Rust ed2k-server

On the `tests/membench` workload at 5 M files (see
[`memory-engine-benchmark.md`](memory-engine-benchmark.md)), the Rust ed2k-server holds
**276 B/file** live and peaks at 1.57 GB RSS. The memory engine holds **327 B/file** and
peaks at 2.62 GB. Until 2026-10-13 it held 703 B/file and peaked at 4.42 GB; that gap,
and where it came from, is analysed in `ed2k-server-rust-comparison.local.md` §7.5.

What the engine took from that comparison is in §2.2: a record of 80 B against Rust's
~80 B `FileRecord`, the hash inside the record, the first source inline, a 24 B source,
the client's address and hash in one place per user, and 4-byte file ids in the
per-user list.

What still differs:

- **The name index.** Rust keys its keyword index by a 32-bit FNV hash of each word and
  never stores the word text. About every 10 minutes it packs its posting lists into
  delta-varint blobs of 1–2 bytes per id. The memory engine stores every distinct word,
  the byte-trigram lists that substring matching needs, and uncompressed 4-byte ids.
  Rust matches whole words only, so it cannot answer a query for part of a word.
- **The file table.** Rust's slab is its hash table (intrusive chains). The engine has
  a Go map from hash to record id beside its slab, about 35 B a file.
- **Media tags.** Rust stores none. The engine stores them for the files that have
  them.
- **The garbage collector.** With the default `GOGC=100` the heap may grow to twice its
  live size before a collection (§6), so the peak sits well above live heap: 2.62 GB
  against 1.56 GB. jemalloc frees memory straight away, so Rust peaks at 1.57 GB on
  1.32 GB live.

Not adopted: **interning repeated names.** The Rust server built it and removed it
again. On its live index of 1.17 M files 2.8% of the names were duplicates, which saved
1.8 MB, while the table that found them cost 29 MB
(`ed2k-server/src/state/name_interner.rs`). The 30% repeated names of the benchmark
workload are far more than a server sees.

---

## 3. If the live network ran eNode-go

Source: `eMuleQt/data/config/server.met`, ten servers, user and file counts as each
advertises them (2024 snapshot). Assumes **1.2 sources per distinct file** — plausible
for eD2K, where most files have one source and a small popular tail has many — which is
369 B per file at the costs of §1. The index column scales in that assumption:
1.0 → −3%, 2.0 → +12%.

| Server | Users | Files | Index | Sessions | Total |
|---|---:|---:|---:|---:|---:|
| eMule Sunrise | 46,516 | 27,397,581 | 9.4 GiB | 727 MiB | **10.1 GiB** |
| eMule Security | 24,361 | 12,181,708 | 4.2 GiB | 381 MiB | **4.6 GiB** |
| !! Sharing-Devils No.2 !! | 6,405 | 3,385,106 | 1.2 GiB | 100 MiB | **1.3 GiB** |
| !! Sharing-Devils No.1 !! | 5,791 | 2,890,296 | 1.0 GiB | 91 MiB | **1.1 GiB** |
| GrupoTS Server | 5,210 | 2,179,848 | 767 MiB | 81 MiB | **848 MiB** |
| !! Sharing-Devils No.3 !! | 4,166 | 1,827,294 | 643 MiB | 65 MiB | **708 MiB** |
| Astra-3 | 3,635 | 1,687,637 | 594 MiB | 57 MiB | **651 MiB** |
| Akteon Server | 2,930 | 1,158,962 | 408 MiB | 46 MiB | **454 MiB** |
| Astra-5 | 2,205 | 1,053,791 | 371 MiB | 35 MiB | **406 MiB** |
| Akteon Server No2 | 1,371 | 828,206 | 291 MiB | 21 MiB | **312 MiB** |
| **All ten combined** | **102,590** | **54,590,429** | **18.8 GiB** | **1.6 GiB** | **20.4 GiB** |

Two observations worth keeping in mind:

- **The index dominates by 12:1.** Users are cheap; files are not. Sunrise's 46k
  concurrent users cost less RAM than 2.1M of its 27.4M files.
- **The whole public network fits in one machine.** All ten servers' indices together
  are 20 GiB — a single 48 GB host could hold the entire advertised eD2K index with the
  memory engine, GC headroom included.

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
  registered. The soft limit therefore bounds a client's **whole** share on the
  server, not the size of one packet.
- **What eNode-go does with it.** Both limits are configured under `files:` — `softLimit`
  defaulting to 10000, `hardLimit` to 20000, the values that used to be hardcoded in
  `BuildGlobServStatResPacket` — and both are enforced. `handleOfferFiles`
  (`ed2k/server_runtime.go`) holds the soft limit against the distinct files a session
  sources: a new file past it is ignored, after one `WARNING` message, and a file the
  session already sources can always be offered again. The hard limit is on one packet:
  an `OP_OFFERFILES` declaring that many records or more gets the client disconnected,
  which a client keeping to the 200-file packet ceiling above never is. The advertised
  numbers and the enforced numbers come from the same two config keys, so a client is
  never told one thing and held to another. See
  [`server-client-communication.md`](server-client-communication.md#per-client-publish-limits).

  This is what makes the middle row below a real ceiling rather than a projection. The
  third row now takes a deliberate act — raising `files.softLimit` — rather than merely a
  client that felt like it.

### 4.2 Scenarios at 44,000 online users

Arithmetic from the measured unit costs in §2 — 358 B per distinct file, 55 B per extra
source, 15.8 KiB per session, 12 MiB base — assuming **1.2 sources per distinct file**, the
same dedup assumption as §3.

Sessions are noise at this scale: 44,000 × 15.8 KiB = **0.66 GiB** regardless of the index.

| Files published per user | Offer records | Distinct files | Index | Total live | Provision (×1.5) |
|---|---:|---:|---:|---:|---:|
| **589** — the network average¹ | 25.9 M | 21.6 M | 7.4 GiB | 8.1 GiB | **~12 GiB** |
| **10,000** — every user at the default soft limit | 440 M | 366.7 M | 126.0 GiB | 126.7 GiB | **~190 GiB** |
| **100,000** — every user at a raised `files.softLimit` | 4.4 B | 3.67 B | 1260 GiB | 1261 GiB | **~1.9 TiB** |

¹ 27,397,581 files / 46,516 users, from eMule Sunrise in the §3 table — the largest server
on the public network, and the closest thing to a measured files-per-user figure we have.

Dedup sensitivity, as in §3: 1.0 source per file → +16%, 2.0 → −33%.

Inverted, the same model says what a given box holds with 44,000 users connected:

| Host RAM | Distinct files | Sustainable files published per user |
|---:|---:|---:|
| 16 GB | 29.1 M | ~790 |
| 32 GB | 60.1 M | ~1,640 |
| 64 GB | 122 M | ~3,330 |
| 128 GB | 246 M | ~6,720 |
| 256 GB | 495 M | ~13,500 |

### 4.3 Reading those tables

- **Only the first row is a real machine.** 44k users sharing at eD2K-typical rates is
  ~12 GiB provisioned — comfortable on a 16 GB host with `GOMEMLIMIT` set (§6). If every
  user filled the default `files.softLimit` of 10,000, the same server is a 190 GiB working
  set, and a `softLimit` raised to 100,000 is 1.9 TiB. Those are the DB engines' territory
  (§7), where the same 44k sessions cost ~0.7 GiB of Go process.
- **Search no longer scans the table.** `MemoryEngine.FindBySearch` used to scan the
  whole map under `RLock`, about 3 s per selective query at 5 M files. Since 2026-09-30
  it answers from the name index in `storage/memory_index.go`, at about 130 µs for a
  rare word at 5 M. Only a query with no term of 3 or more bytes, or with every term in a
  large share of the files, still scans. A search with more matches than the
  `MaxSearchResults` cap reads up to 20,000 of them and returns the ones with the most
  sources, which costs a few milliseconds for a common word
  (`docs/memory-engine-benchmark.md`). The index is included in the figures above; it
  costs from about 4 B per word of a name, where the words are known, to ~170 B per file
  where every name brings a word of its own.
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
  that means a 16–24 GB host; for the mid-tier servers 2–3 GB; for Akteon No2 under 1 GB.
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
  forever — that is a policy choice with a directly measurable RAM price of about 360 B
  per retained file.

---

## 7. Database engines

With `storage.engine: mysql` or `mongodb` the file index is not in the Go process at
all. The process then costs:

- 12 MiB base,
- ~16 KiB per online session (identical — it is the connection, not the engine),
- plus the transient working set of in-flight searches.

So eMule Sunrise's 46,516 users would be **~730 MiB of Go process**, and the 9.4 GiB of
index becomes the database's problem, where it is paged rather than resident. That is
the trade: RAM for query latency.

### 7.1 A 50,000-user server on MariaDB

`storage.engine: mysql`, `dialect: mariadb`, 50,000 online users. The Go-side figures are
the measured unit costs of §2.3. **The MariaDB figures are arithmetic from the schema in
[`misc/enode.sql`](../misc/enode.sql), not measured** — load the table and read
`information_schema.TABLES` (`DATA_LENGTH`, `INDEX_LENGTH`) plus the `FTS_*` auxiliary
tables before buying hardware on them.

#### eNode-go process

| Item | Size |
|---|---:|
| Base | 12 MiB |
| Sessions: 50,000 × 15.8 KiB | 771 MiB |
| **Live total** | **~0.8 GiB** |
| With GC headroom (×1.5, §6) | ~1.2 GiB |
| `pendingResults` (§8), ~200 KB per paging session | ~1 GB at 10% of users; 9.3 GiB worst case |
| Meta search, only if enabled (2 feeds × 250k rows × ~1 KB + 1,000 × 100-row query cache) | ~0.6 GB |
| Kernel socket buffers (outside RSS, §6) | 0.2–0.5 GB |

Provision **2–4 GB** and set `GOMEMLIMIT=3GiB`.

#### MariaDB data

Volume follows files per user, not users. At the network average of **589 files per user**
(§4.2) and 1.2 sources per distinct file (§3): 29.5 M `sources` rows and 24.5 M `files`
rows.

| Table | Rows | Bytes/row (row + indexes + page fill) | Size |
|---|---:|---:|---:|
| `sources` — clustered row ~160 B (60-char name, empty tag columns), 9 secondary indexes ~250 B, `name_ft` FULLTEXT ~150 B | 29.5 M | ~550 | ~16 GB |
| `files` — clustered row ~90 B, 4 secondary indexes ~170 B (random-hash inserts leave pages ~50–70% full) | 24.5 M | ~270 | ~6.6 GB |
| `clients` — online plus not-yet-swept offline rows | 50k–1 M | ~150 | < 0.2 GB |
| **Total** | | | **~23 GB (20–30 GB)** |

**Size `innodb_buffer_pool_size` to hold all of it — ~28 GB.** Every login re-offers the
client's whole share, and the `ON DUPLICATE KEY UPDATE` upserts hit random pages of the
`hash`, `hash_size` and `id_file+id_client` indexes. Unique keys cannot use the change
buffer, so a pool smaller than the indexes turns most offers into random disk reads.

As with the memory engine, `files.softLimit` is the lever (§4.1). With every user at the
default 10,000, the same arithmetic gives ~500 M sources and ~417 M files: **~390 GB**,
which no longer fits a buffer pool on ordinary hardware.

#### Load to plan for (assumptions, not measured)

| Operation | Assumption | Rate |
|---|---|---:|
| Logins | 2 h average session | ~7/s |
| Offers | 589 files per login, 200 per packet | ~21 packets/s, ~4,100 source upserts/s |
| Searches | 1 per user per 5 min | ~170/s |
| Source lookups | ~50 downloads per user, re-asked every 20 min | ~2,000/s |

**Throughput is the wall, not RAM.** The only measured load
([`remote-database.local.md`](remote-database.local.md) §5.4) topped out at ~262
operations/s on the default 8 connections, p50 ~100 ms, in Docker on a development machine
— well below the rates above. InnoDB FULLTEXT on ~30 M rows is CPU-heavy for common words,
and the offer/counter-refresh deadlocks described in that document's §6.1 grow with offer
rate. Load-test at this scale before committing to hardware.

#### Server specs

Two hosts (recommended):

| | eNode-go host | MariaDB host |
|---|---|---|
| CPU | 4 vCPU | 8–16 cores |
| RAM | 4–8 GB | 48 GB (28 GB pool, per-connection buffers, FTS cache, OS) |
| Disk | 20 GB (logs) | NVMe RAID1, 250–500 GB, ≥ 20k random IOPS |
| Network | 1 Gbit port, ~50–100 Mbit/s sustained | private link, RTT < 1 ms (the DSN has no TLS) |

One host: 16 cores, 64 GB RAM, 2 × 1 TB NVMe RAID1, 1 Gbit.

MariaDB settings:

- `innodb_buffer_pool_size=28G`, `innodb_log_file_size=4G`.
- `innodb_flush_log_at_trx_commit=2` and binlog off unless replicating — the index is
  rebuilt by clients re-offering, so losing the last second on a crash is acceptable.
- `max_connections` ≥ 100, with eNode's `storage.mysql.connections` raised from 8 to
  32–64.
- `innodb_ft_total_cache_size` 1–2 GB; optionally `innodb_ft_enable_stopword=OFF` (rebuild
  the index afterwards, see [`database-engines.local.md`](database-engines.local.md)).

eNode-go host OS limits: `ulimit -n` ≥ 131072, `nf_conntrack_max` ≥ 256k if conntrack is
active, `net.core.somaxconn` 4096, default socket buffer sizes.

---

## 8. Caveats

- **`pendingResults` pins search tails.** A session that ran a search wider than one
  page holds up to `storage.MaxSearchResults` (1000) `File` values until it pages
  through them or issues another search — ~200 KB per session worst case. Bounded, but
  46k sessions all doing it at once is 9 GB. It is the one per-session cost that is not
  a flat 16 KiB.
- **`MaxWireSources` (255) caps the tail, not the storage.** The engine stores every
  source; only the reply is truncated. A file with 5,000 sources costs 5,000 records.
- **RAM is now the first wall on a large memory-engine index.** Until 2026-09-30
  `FindBySearch` was a full map scan under `RLock`, which became a CPU and lock-hold
  problem long before memory ran out. It now answers from the name index (§4.3), and
  §2.2 says where a file's bytes go.
