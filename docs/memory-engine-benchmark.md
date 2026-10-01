# Memory engine benchmark

`tests/membench` measures the memory storage engine at scale: how fast files are
published, how much heap each file costs, and how long `FindBySearch` takes. The
workload is the same as `examples/loadgen.rs` in the Rust ed2k-server, so the numbers
can be compared directly with that server.

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
| `ENODE_MEMBENCH` | unset | `1` runs `TestMemoryEngineScale` |
| `ENODE_MEMBENCH_FILES` | `100000,1000000` | comma-separated engine sizes |
| `ENODE_MEMBENCH_QUERIES` | `200` | queries per kind and size |

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
