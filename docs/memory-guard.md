# Memory guard

The memory guard (package `memguard`) keeps a load spike from ending in an
out-of-memory kill. It does two things:

1. It gives the Go GC a **soft memory limit** (`debug.SetMemoryLimit`), so the GC
   runs more often as the process nears the limit, rather than letting the heap grow
   to twice its live size (`GOGC=100`).
2. After **every GC cycle** it compares the live heap with that limit. Above
   `shedAtPercent`, it tells the caches to **shed**: expired entries first, then the
   least recently used, until each keeps `keepPercent` of its bytes. Entries are
   dropped before their TTL runs out. The next GC frees them.

Caches it sheds:

| Name | Cache | Bound |
|---|---|---|
| `metaSearch` | eD2K meta search answers (`metaSearch.cache`) | `maxEntries`, `maxBytes` |
| `metaApiSearch` | MetaApi.Search chunks (`metaApi.search.cache`) | `maxEntries`, `maxBytes` |
| `metafile` | verified metafiles (`metaApi.metafileCache`) | `maxBytes` |

Everything it drops can be fetched again from the daemons. A shed costs some daemon
calls, never data.

## Why the GC can't do this on its own

Go has no soft references, that is, pointers the GC clears only when memory is
short:

- `weak.Pointer` (Go 1.24) is cleared at the **next** cycle whatever the pressure. At
  this server's allocation rate a cycle runs every few seconds, so a weak cache would
  always be empty.
- A memory limit alone (`GOMEMLIMIT`) makes the GC run harder, but it cannot free what
  a cache still references. With a full cache near the limit, the GC runs back to back
  (a "death spiral") and the process still grows.

So the guard pairs the limit with a hook that releases references.

## The limit

The guard takes the first of these that applies:

1. `memory.limitBytes` when above 0 (source `config`).
2. `GOMEMLIMIT` from the environment (source `GOMEMLIMIT`). The runtime applies it
   itself, and the guard reads it.
3. `autoPercent` (default 75%) of the cgroup memory limit: cgroup v2 `memory.max`, then
   v1 `memory.limit_in_bytes` (source `cgroup`; Linux only).
4. `autoPercent` of physical RAM (source `ram`; Linux, macOS, Windows).
5. Nothing found: no limit and no shedding (source `none`).

`memory.enabled: false` turns the guard off (source `off`). Any limit from
`GOMEMLIMIT` still stands.

75% leaves room for what the Go limit does not see: the C heap of the MySQL or MongoDB
drivers, the kernel's socket buffers, and other processes on the box. With a dedicated
container, 85–90% is fine. On a shared host, give `limitBytes` explicitly.

## Config

```yaml
memory:
  enabled: true
  limitBytes: 0          # 0 = GOMEMLIMIT, else autoPercent of the cgroup limit or RAM
  autoPercent: 75
  shedAtPercent: 80      # live heap above this share of the limit makes the caches shed
  keepPercent: 50        # each cache keeps this share of its bytes per shed
```

The whole section is reloadable. A reload applies the new limit and percentages to
the running process.

`keepPercent` 0 means the default (50). At most one shed runs per second. While the
heap stays above the threshold, each shed halves the caches again, so they drain
within a few seconds of sustained pressure. Once the heap falls back, they refill
normally.

## How it hooks the GC

A sentinel object carries a `runtime.AddCleanup` callback. The callback runs once the
GC has found the sentinel unreachable, which is after the next cycle. It then arms a
new sentinel, so the guard sees every cycle. The callback only signals a worker
goroutine. The worker reads `/gc/heap/live:bytes` from `runtime/metrics` (no
stop-the-world) and sheds if needed. The guard never forces a GC and never calls
`FreeOSMemory`: with the limit set, the runtime returns freed pages to the OS itself.

## Watching it

The admin dashboard's **Runtime** tab (`GET /api/runtime`, field `memory`) shows:

- the limit and where it came from;
- the live heap at the last GC and its share of the limit;
- the shed count, with the time and bytes of the last shed;
- each cache's entries and estimated bytes.

Every shed is also logged at warn level:

```
memory pressure: live heap 1180 MiB of 1400 MiB limit (shedAt 80%), caches shed 210 MiB (metaSearch 110 MiB, metaApiSearch 90 MiB, metafile 10 MiB)
```

Frequent sheds mean the limit is too low for the load. Raise it, or lower the caches'
`maxBytes` so they stop filling to the point where pressure begins.

## Cache byte estimates

`meta.FileRowsBytes` and `meta.ChunkBytes` add up struct sizes plus the bytes of each
string and byte slice. They ignore allocator rounding and strings shared with other
values. `meta/cachesize_test.go` holds them within 2× of a measured heap; on
realistic rows they come out within about 1%. A metafile counts its content bytes.
