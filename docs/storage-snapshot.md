# Memory-engine snapshots

The `memory` storage engine is the default and holds its whole index in RAM, so a
restart used to start from nothing and re-learn everything from client re-offers.
This persists that index to a gob file — periodically and on shutdown — and reloads
it at startup.

Off by default. It applies to the `memory` engine only: `mysql` and `mongodb`
already persist, and enabling the key under those logs one line and does nothing.

---

## Enabling

```yaml
storage:
  engine: memory
  snapshot:
    enabled: false            # off by default
    file: "data/storage.gob"  # written by the server, hence under data/
    intervalMinutes: 15
    compress: true            # gzip the gob; the reader detects either form
```

Present in both shipped configs (`enode.config.yaml` and `enode.local.yaml`), off
in both. `file` is resolved the same way `gossip.serverMetFile` is — relative paths
resolve against the module root, so the server writes one `data/` no matter which
directory it was started from.

Startup and shutdown each log one line:

```
storage snapshot: restored 1204331 file(s) from data/storage.gob in 3.1s
  (2841002 source(s) and 41233 client(s) in the file were not restored:
   they are offline after a restart)
storage snapshot: wrote 1204331 file(s), 2841002 source(s), 41233 client(s)
  to data/storage.gob (118.4 MiB, 4.2s, shutdown)
```

---

## What a restore gives you, and what it does not

The snapshot deliberately reproduces **what a mysql- or mongodb-backed server looks
like after a restart**, not what the memory engine held when the file was written.

Both database engines reset every liveness flag at startup — `UPDATE clients SET
online = 0` and the same for `sources` (`storage/engine_mysql.go`,
`storage/engine_mongodb.go`). Their source lookups require `online = 1` on both the
source and its client, while their *searches* do not filter on `online` at all. The
consequence, on any of the three engines:

| After a restart | Result |
|---|---|
| Search for a known filename | **Hits** — names, sizes and counters all survive |
| Source list for one of those files | **Empty**, until the owning client reconnects and re-offers |
| `ClientsCount()` / dashboard "clients" | **0** |
| `File.Sources` counter | The **pre-restart** value, until the first cleanup sweep |

So the file carries clients, files and sources — the same three entities the
database engines store — but the loader installs only the files. Clients and
sources are counted for the log line and dropped, which is what `online = 0` amounts
to for an engine with no offline representation.

Restoring them instead would be actively wrong: the server would hand out sources
for peers that are not connected to it, and LowID ids that the pool has since
reassigned to somebody else.

**The stale `File.Sources` count is parity, not a bug.** In SQL, `files.sources` is
a `COUNT(*)` over every source row, online or not, and nothing recomputes it at
startup either. `CleanupStale` brings both back in line on its first sweep.

`servers` is not persisted, because no engine persists it — it is a plain in-RAM
slice on all three, rebuilt from `servers:` on every boot by `seedServers`.

### The limit worth knowing

`MemoryEngine.Disconnect` deletes the client and strips its sources, where the
database engines keep both offline until `CleanupStale` expires them. A snapshot can
therefore only ever contain what was **online at the moment it was written**. A
mysql-backed server keeps a rolling `staleAfterHours` window of recently-departed
peers whose filenames stay searchable; the memory engine has no equivalent, because
the information is gone before any snapshot could see it. Closing that gap means
adding online flags and timestamps to the in-RAM structs.

---

## Format

One gob stream: a header, then a sequence of batches read until `io.EOF`.

```
SnapshotHeader{ Magic, Version, WrittenAt, Engine, Files, Clients, Sources, NextClientID }
SnapshotBatch{ Files []File, Sources []SnapshotSources, Clients []ClientInfo }
SnapshotBatch{ ... }
...
```

- **Magic and version are checked before anything is decoded.** A foreign file fails
  with a message naming the problem, and an unknown version is refused outright
  rather than half-understood — whatever such a file decoded to would be served.
- **The header counts are advisory.** They are what the engine held when the write
  began, and are used to pre-size the maps on load.
- **`NextClientID` is restored** so a `StoreID` can never be reissued to a live
  session while a restored record still claims it — the memory-engine stand-in for
  `clients.id AUTO_INCREMENT`.
- **Compression is sniffed, not configured, on read.** The loader looks for the gzip
  magic (`1f 8b`), so flipping `compress` does not orphan the file already on disk.

## How the write avoids stalling the server

The index can be very large — `docs/memory-footprint.md` measures ~560 B of live
heap per file, so a 27M-file index is around 15 GiB. Holding the engine's lock
across a write that size would block every login and every `OP_OFFERFILES` for as
long as it took.

So the write is chunked:

1. One pass under `RLock` captures the file keys into a single flat `[]byte` of
   24-byte records — the 16-byte hash followed by the big-endian size, which is the
   `files` map key (a `[]string` would cost more in slice headers than in keys) — the
   client records, and the counts. The stride is fixed, so a key of any other width is
   skipped; skipping *every* key would leave an empty buffer, which the writer cannot
   tell apart from an engine holding nothing and so would write no file at all.
2. Each batch of 10,000 keys then takes `RLock` on its own, copies those entries out
   — deep-copying the `[]byte` fields, since `AddFile` mutates source records in
   place — releases the lock, and encodes.

The lock is held for milliseconds at a time instead of for the whole write, and peak
extra memory is one batch rather than a second copy of the index.

The cost is a **slightly torn snapshot**: a file added or deleted mid-write may land
without its sources, or be captured in the key list and gone by the time its batch is
copied. Both are tolerated — a key that has disappeared is skipped, and a source
group naming a file that is not in the snapshot is skipped on load. This is a cache,
not a ledger.

## Durability

- The file is written to a temporary name in the same directory, `fsync`ed and
  renamed into place, so a crash mid-write cannot leave a truncated index that the
  next start would read as a short one. Same idiom as `WriteServerMet`.
- **An empty engine never overwrites a good snapshot.** A server that has just
  started holds no files, and its first scheduled write would otherwise truncate the
  file it was about to be restored from.
- **The shutdown write blocks.** The stopper waits for the final encode to finish
  rather than only signalling it, because `main`'s remaining defers would otherwise
  race the process exit — which a snapshot of any real size loses every time.
- A write failure is a warning, never fatal. A read failure at startup is also a
  warning: the server boots with an empty index and rebuilds from re-offers.
- A truncated tail (from a kill during an earlier write that somehow survived the
  rename) keeps the batches already decoded rather than discarding the whole file.

## Sizing

Disk is roughly proportional to the RAM figures in
[`docs/memory-footprint.md`](memory-footprint.md), and well below them — the gob
carries the payload without Go's map overhead, allocator rounding, or the duplicated
hash keys that account for about a third of the in-RAM cost.

As a planning figure, **~120 MB per million files compressed, ~250 MB uncompressed**,
plus the source records. Compression roughly halves it and usually shortens the
write, since filenames compress well and the disk does less work.

Note the interval interacts with a crash, not with a clean stop: shutdown always
flushes, so `intervalMinutes` only bounds how much of the index a `SIGKILL` or a
power loss can cost.

## When not to use it

- **On `mysql` or `mongodb`.** They already persist. The key is a no-op there.
- **When the index churns faster than it is worth reloading.** A small server whose
  clients all reconnect within a minute rebuilds its index from re-offers anyway.
- **When disk is tighter than RAM.** At Sunrise scale the file is several GB.

The strongest case is a large memory-engine server where the index took hours to
accumulate and a restart would otherwise leave searches empty until the population
reconnects.
