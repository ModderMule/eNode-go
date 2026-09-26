# Torrent and Usenet results in eD2K search

eNode-go can merge releases from two catalogue daemons into the answer to an
ordinary eD2K search:

- torrent-crawler, which crawls the Mainline DHT;
- usenet-crawler, which builds NZBs from Usenet headers.

Both TCP (`OP_SEARCHREQUEST`) and UDP (`OP_GLOBSEARCHREQ*`) searches are covered.
The rows arrive in the same reply as the eD2K files. Each row's filename starts with
a prefix, so every client can see which network it came from.

The design and its reasoning are in `docs/meta-search-torrent-usenet-plan.local.md`.
This page describes what is implemented.

## Wiring

```
eMule client ──OP_SEARCHREQUEST / OP_GLOBSEARCHREQ*──► eNode-go
                                                        │ storage.FindBySearch   (eD2K files)
                                                        │ meta.Searcher.Search   (in parallel)
                                                        │   ├─ feed (in memory)
                                                        │   ├─ result cache
                                                        │   └─ MetaIngest.Search ──► torrent-crawler :9701
                                                        │                        ──► usenet-crawler  :9702
◄──────────── one OP_SEARCHRESULT / N × OP_GLOBSEARCHRES ┘
```

The contract is the `enode.meta.v1` `MetaIngest` service. It is defined in the shared
[`enodemeta`](https://github.com/ModderMule/enodemeta) module, which this repository
includes as a **git submodule** at `./enodemeta` (`go.mod` reaches it with a
`replace`). Clone with `--recurse-submodules`, or run `git submodule update --init`.

The generated code must be imported from there, never regenerated here: protobuf-go
panics when the same descriptor is registered twice. eNode-go speaks the Connect
protocol to the daemons over HTTP/1.1 or HTTP/2. Each daemon serves Connect, gRPC and
gRPC-Web from the same handler.

The code lives in `meta/`. It holds everything that depends on the contract or on
connect. `ed2k/` only sees the `MetaSearcher` interface in `ed2k/metasearch.go`.

## What a row looks like

Each daemon row becomes one ordinary search record:

| Field | Value |
|---|---|
| hash | The 16-byte **meta hash** (`ED 2B 01 …`), minted by eNode-go from the row's identity (infohash or NZB digest) by `enodemeta/metahash`. A daemon never supplies it. |
| client ID / port | `0` / `0`. eMule records no source. |
| `FT_FILENAME` | `namePrefix` + the release's name. |
| `FT_FILESIZE` | The selected file's size, or the release's total size for a whole-set row. |
| `FT_FILETYPE` | The daemon's eD2K type string. |
| `FT_SOURCES`, `FT_COMPLETE_SOURCES` | Torrent seeders capped at 99, which stays below eMule's spam heuristic. `0` for an NZB, which has no sources. |
| `0x60`–`0x6C` | `FT_META_KIND`, `_VERSION`, `_FILEINDEX`, `_FILEPATH`, `_TOTALSIZE`, `_ID`, `_SEEDERS`, `_PEERS`, `_AGE`, `_INDEXER`, `_FLAGS`, `_MAGNET` |

A stock eMule shows these rows normally, prefix included. A download started from
one never finds a source. A capable client such as eMuleQt reads the `FT_META_*` tags
and hands the release to its own BitTorrent or Usenet engine instead.

**Guard.** `OP_OFFERFILES` drops any record whose hash parses as a meta hash
(`metahash.RejectOfferedFile`). Without it, a modified client could attach itself as
a "source" of an advertised row. `OP_GETSOURCES` on a meta hash returns an empty list.
Tests pin both behaviours.

## How a search is answered

1. The eD2K search tree is reduced to a `meta.Query` (`meta/query.go`):
   - Keywords on the AND path become the query.
   - A single word under AND NOT becomes an `exclude`.
   - The file type and the size bounds carry over.
   - OR branches are dropped. That widens the query, which is safe.
   - A tree with no required keyword (for example `a OR b`) makes no live call.
2. Every enabled network is queried in parallel, alongside `FindBySearch`. Each network:
   - takes its matches from the **feed**, if one is subscribed;
   - if the feed has not filled its quota, gets a **cache** hit or makes a **live**
     `MetaIngest.Search` within its deadline.
3. Every row is run through `storage.MatchSearchExpr` against the **full** tree and its
   unprefixed name. This keeps OR, NOT and extension constraints exact. It also means
   the prefix itself can never match a keyword.
4. eD2K files come first, then the torrent rows, then the Usenet rows. The total is
   capped at `storage.MaxSearchResults`. The existing 255-row paging
   (`OP_QUERY_MORE_RESULT`) is unchanged.

A daemon that is slow, down, or has no search index adds at most its deadline to the
search and contributes nothing. It never fails the search. If a daemon answers
`unavailable`, `unimplemented` or `unauthenticated`, live calls to it pause for 30 s,
so each search does not pay for that answer again.

### UDP

A UDP search runs on a shared worker, and every row costs one datagram. So a UDP
search:

- has a shorter deadline (`udpSearchTimeoutMs`);
- has a smaller per-network cap (`maxUDPResults`, at most 50);
- makes a live call only while one of `udpMaxConcurrent` slots is free.

When no slot is free, the search is answered from the feed and cache only.

## Who receives the rows

`metaSearch.advertiseToLegacyClients` defaults to **true**, so every client receives
meta rows. When it is `false`, only these requesters do:

- a TCP client whose login `CT_SERVER_FLAGS` includes `SRVCAP_METASEARCH` (`0x2000`);
- a UDP `OP_GLOBSEARCHREQ3` whose `CT_SERVER_UDPSEARCH_FLAGS` includes
  `SRVCAP_UDP_METASEARCH` (`0x02`).

`OP_GLOBSEARCHREQ` and `…REQ2` have no tag block, so they never qualify.

While any network is enabled, the server sets `FlagMetaSearch` (`0x10000`) in its
TCP and UDP flag words. Clients ignore unknown bits.

## Feed

With `feed.enabled`, eNode-go subscribes to the daemon's published set and keeps it
in memory. Those releases then match without a round trip. On every process start the
subscription asks for a snapshot (`after_seq = 0`), so no cursor is persisted. A
reconnect within the same process resumes from the last applied cursor. A reconnect
that interrupts a snapshot restarts it. `reset`, upsert/retract and `snapshot_end` are
applied as `enodemeta/docs/ingest-contract.md` specifies.

`maxRows` caps the rows held. A row costs about 1 KB, so the default of 250 000 rows
is about 250 MB.

## Configuration

`enode.config.yaml` documents every key. Summary:

```yaml
metaSearch:
  advertiseToLegacyClients: true
  udpMaxConcurrent: 16
  torrent:                          # usenet: the same keys, url :9702, "[usenet] "
    enabled: false
    url: "http://127.0.0.1:9701"
    token: ""                       # the daemon's ingest.auth_token; keep it in enode.local.yaml
    namePrefix: "[torrent] "        # "" for none
    liveSearch: true
    searchTimeoutMs: 1500
    udpSearchTimeoutMs: 800
    maxResults: 50
    maxUDPResults: 10
    countInServerStatus: false      # add this network's files to the server status total
    feed:
      enabled: false
      maxRows: 250000
      reconnectMinSeconds: 5
      reconnectMaxSeconds: 300
  cache:                            # live Search answers, keyed by keywords/excludes/type/size
    enabled: false
    maxEntries: 1000
    maxRowsPerEntry: 100
    ttlSeconds: 600
```

The server refuses to start in these cases:

- an enabled network's `url` is not `http(s)://host:port`;
- `maxUDPResults` is above 50;
- `maxResults` is above 1000;
- `reconnectMaxSeconds` is below `reconnectMinSeconds`.

It logs a warning at startup when an enabled daemon is not on loopback and no token
is set.

## Server status and the dashboard

### File total

With `metaSearch.<network>.countInServerStatus`, a network's files are added to the
file total that eD2K clients see in `OP_SERVERSTATUS` and `OP_GLOBSERVSTATRES`. Which
number is added depends on `liveSearch`:

- **`liveSearch` on:** the daemon's `GetInfo.files`, the number of files its
  catalogued releases hold. A live search can reach every one of them. eD2K counts
  files, not releases, and a multi-file release shows up as one search row per file,
  so the contract carries this count separately from `catalogued`.
- **`liveSearch` off:** only the feed can answer, so the count is the rows the feed
  holds.

Each network's `GetInfo` is polled at start and then every minute, with a 5 s
deadline. The status path reads only the last answer, so a status reply never waits
on a daemon. If a poll fails, the last figures are kept, so a daemon restart does not
make the advertised total dip. The sum is clamped to the packets' `uint32`.

The setting is off by default. Clients mostly only display the number: in the
server list, in network info, and when adding up totals. There is one exception.
eMule's and eMuleQt's **automatic** search type chooses the server over Kad only when
all of these hold:

- the server has more than 40 000 users (and fewer than 2 million);
- it advertises more than 5 000 000 files;
- the client's server list has fewer than 40 servers.

Counting catalogue files can push a large server past the 5 000 000 line.

### Admin dashboard

The dashboard's Files card shows the eD2K count. When counted networks add to the
total, a line under it shows the advertised total. When meta search is on, a
**Torrent / Usenet** section adds one card per network. Each card shows:

- whether the daemon is reachable, or live search is paused after an
  unavailable/unimplemented/unauthenticated answer (the last error appears on hover);
- the daemon's name and version;
- catalogued releases and files, and the published count;
- the live-search state, and whether the daemon has a search index;
- feed rows and releases held, and whether the feed has caught up, or how far its
  cursor lags the daemon's `last_seq`;
- search counters since start: TCP and UDP searches, rows served, live calls with
  their errors and timeouts, cache hits against lookups, and UDP searches that made no
  live call because every `udpMaxConcurrent` slot was taken;
- what the network adds to the server status file total.

The same figures are in `/stats.json`: `advertisedFiles`, `metaCacheEntries`, and the
`meta` array.

## Downloading a row

The `.torrent` / `.nzb` behind a row is served by the client-facing Meta API
(`FetchMetaFile` proxy with verification, `ST_META_API` discovery, optional
accounts). See [meta-api.md](meta-api.md).

Clients can also search the catalogues directly, with paging and a torrent / Usenet /
both selector, through `MetaApi.Search`. See [meta-api.md](meta-api.md#searching-the-catalogues).

## By design / deferred

- Rows are held in memory only (feed and caches). Persisting them in the MySQL/MongoDB
  engines is not planned: the caches are enough.
- Content filtering of meta rows by name is deferred. eNode-go has no filename filter
  (`filter:` is IP and country only); category filtering is configured in the
  crawlers.
