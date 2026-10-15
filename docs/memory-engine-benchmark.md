# Memory engine benchmark

`tests/membench` measures the memory storage engine at scale: how fast files are
published, how much heap each file costs, and how long `FindBySearch` takes. The
workload is the same as `examples/loadgen.rs` in the Rust ed2k-server, so the numbers
can be compared directly with that server.

A second case, `TestHugeClient`, measures one session that shares a very large number
of files: see [One huge client](#one-huge-client).

## Workload

For N files:

- every file has one source, and there are N/614 users;
- 70% of the names are distinct;
- each name has 7 words, drawn from a vocabulary of 0.72·N words (`w<number>`), and ends in `.bin`.

Files are published through `Connect` and `AddFile`, the same path a session uses.

The suite runs these query kinds:

| Kind | Query |
|---|---|
| `rare1` | one word of a stored name |
| `and2` | two words of a stored name, ANDed |
| `substr` | a 4-character piece from inside a word, which only a substring match finds |
| `common` | `bin`, which is in every name |
| `miss` | `zzqxv`, which is in none |

`rare1`, `and2` and `substr` must return hits, so a broken index fails the run
instead of timing empty answers.

## Running

The scale test is skipped unless `ENODE_MEMBENCH=1` is set:

```sh
ENODE_MEMBENCH=1 go test ./tests/membench -run Scale -v
ENODE_MEMBENCH=1 ENODE_MEMBENCH_FILES=1000000,5000000 ENODE_MEMBENCH_QUERIES=200 \
  go test ./tests/membench -run Scale -v -timeout 60m
```

| Variable | Default | Meaning |
|---|---|---|
| `ENODE_MEMBENCH` | unset | `1` runs `TestMemoryEngineScale` and `TestHugeClient` |
| `ENODE_MEMBENCH_FILES` | `100000,1000000` | comma-separated engine sizes |
| `ENODE_MEMBENCH_QUERIES` | `200` | queries per kind and size |
| `ENODE_MEMBENCH_HUGE` | `100000` | files the one session of `TestHugeClient` shares |

For before/after comparisons with `benchstat`, `BenchmarkFindBySearch` runs each query
kind against a fixed engine of 200 000 files:

```sh
go test ./tests/membench -run '^$' -bench FindBySearch -benchmem -count 10 > new.txt
```

## Reading the output

```
input: files=5000000 users=8143 unique_names=3500000 vocab=3600000 queries=200
publish: 19.66s  254303 files/s
mem: live=3352.6 MB (703.1 B/file)  maxrss=4474.7 MB
search rare1   mean=       142.3us p50=       128.2us p99=       332.5us avg_hits=23.8
```

- `live` is the growth in `HeapAlloc`, measured after a forced GC, across publishing.
- `maxrss` is the peak resident set of the whole test process.
- `avg_hits` is capped by `storage.MaxSearchResults` (1000).

Results from 2026-09-30 on an Apple M3 Max, before and after the name index
(`storage/memory_index.go`):

| 5 M files | Scan | Indexed |
|---|---|---|
| Heap per file | 568 B | 703 B |
| Peak RSS | 3.69 GB | 4.47 GB |
| Publish | 731 k files/s | 254 k files/s |
| `rare1` p50 | 2.88 s | 128 µs |
| `and2` p50 | 3.60 s | 221 µs |
| `substr` p50 | 147 ms | 2.0 ms |
| `common` p50 | 555 µs | 176 µs |
| `miss` p50 | 2.67 s | 0.2 µs |

The synthetic vocabulary adds 0.72 new words per file, which is far more than real
file names do. The index's per-word cost is therefore close to a worst case here.

Results from 2026-10-13 on the same machine, before and after the compact record
layout and the ranked search (`storage/storage.go`, `storage/memory_rank.go`). Both
columns include the name index:

| 5 M files | Before | After |
|---|---|---|
| Heap per file | 703 B | 327 B |
| Peak RSS | 4.42 GB | 2.62 GB |
| Publish | 231 k files/s | 280 k files/s |
| `rare1` p50 | 149 µs | 130 µs |
| `and2` p50 | 239 µs | 243 µs |
| `substr` p50 | 2.3 ms | 10.5 ms |
| `common` p50 | 259 µs | 3.2 ms |
| `miss` p50 | 0.2 µs | 0.2 µs |

| 1 M files | Before | After |
|---|---|---|
| Heap per file | 729 B | 330 B |
| Peak RSS | 999 MB | 543 MB |
| Publish | 268 k files/s | 332 k files/s |
| `rare1` p50 | 31 µs | 30 µs |
| `and2` p50 | 42 µs | 48 µs |
| `substr` p50 | 948 µs | 1.4 ms |
| `common` p50 | 247 µs | 2.9 ms |

The two searches that got slower are the ones with more matches than
`storage.MaxSearchResults`. Such a search used to stop at its first 1,000 matches, in
publication order. It now reads up to 20,000 of them (`searchRankScan`) and returns
the 1,000 with the most sources, so that one large share cannot fill the answer to a
common word. A search with fewer matches than the cap does the same work as before.

## One huge client

`TestHugeClient` builds the 100,000-file workload above as background, then has one
more session publish 100,000 files of its own, 200 per `AddFiles` call as a client's
packets arrive. It reports:

- the publish rate and the heap per file of that one session's share;
- how long its `Disconnect` takes;
- the longest a search from another goroutine waited while the disconnect ran, and
  while the same share was stored again in a single 100,000-file `AddFiles`.

The search timed is one that matches nothing. It costs under a microsecond by itself,
so its latency is the time it waited for the engine's lock. The garbage collector is
off while latencies are taken, so a collection is not read as a lock wait.

```sh
ENODE_MEMBENCH=1 go test ./tests/membench -run HugeClient -v
```

```
input: background_files=100000 huge_client_files=100000 packet=200
publish: 0.170s  589782 files/s
mem: huge client live=21.2 MB (222.0 B/file)
search idle: mean=0.66us p99=4.8us max=17.2us
disconnect: 0.730ms for 100000 files
search during disconnect: n=34986 mean=0.61us p99=2.5us max=33.4us (longest wait on the engine lock)
one-packet offer of 100000 files: 34.682ms; search during it: n=32595 p99=6.5us max=400.7us
```

Results from 2026-10-13, the range over three to six runs each. "Chunked" is the lock
being released every 1,000 files of a disconnect and every 500 of an offer; "compact"
adds the record layout of [`memory-footprint.local.md`](memory-footprint.local.md) §2.2.

| 100,000 files from one session | Before | Chunked | Chunked + compact |
|---|---|---|---|
| Publish | 425–490 k files/s | 455–479 k files/s | 577–672 k files/s |
| Heap per file of the share | 585 B | 585 B | 222 B |
| Disconnect, total | 20–28 ms | 21–27 ms | 0.58–0.73 ms |
| Longest search wait during the disconnect | 20–28 ms | 0.43–0.53 ms | 0.03–0.04 ms |
| One 100,000-file offer, total | 53–76 ms | 63–69 ms | 27–36 ms |
| Longest search wait during that offer | 53–76 ms | 0.57–0.78 ms | 0.19–0.40 ms |

Before, a disconnect held the engine's write lock from its first file to its last, so
the longest wait is the disconnect itself. With the compact layout the longest wait
during a disconnect is what an idle engine shows too (0.02–0.04 ms): it is scheduling
noise, not the lock. The heap per file is lower than in the scale test because this
share's words are already in the index: it is the cost of the records, their names and
their sources.
