# Access filters — IP ranges and GeoIP

Who may talk to this server at all. Two independent, optional layers in the
`netfilter` package:

- a **static IP-range list** in the eMule/`guarding.p2p` `ipfilter.dat` format, and
- **country blocking** from a MaxMind GeoLite2 database.

Both are off by default: each needs operator-supplied data no default can invent.

---

## 1. Where the drop happens

A blocked address is refused **before any wire parsing**, on both transports:

- **UDP** — the first statement of the datagram handler, ahead of `NewUDPCrypt` and any
  decryption. A blocked address costs one binary search and nothing else, which is the
  whole point on a socket that can be flooded.
- **TCP** — the first statement of the connection handler, before `newTCPClient`. No byte
  is read and no session goroutine, status ticker or crypt state machine is created.

The TCP connection is closed **silently**, with no `OP_SERVERMESSAGE` explaining why.
That is deliberate: the reply would cost a round trip to an address we have already
decided not to serve, and it confirms to a scanner that it found an eD2K server.

The protocol layer sees only a small interface (`ed2k.AccessFilter`), so `ed2k` gains no
dependency on MaxMind and tests can substitute a stub. A nil filter blocks nothing, so
neither call site needs a branch when filtering is off.

---

## 2. IP-range filter

### File format

Both line forms found in the wild are accepted from the same file, because both exist
among the lists operators actually feed a server:

```text
# eMule / guarding.p2p ipfilter.dat — dash range, zero-padded octets
000.000.000.000 - 000.255.255.255 , 000 , Private-Use Networks
1.2.3.4 - 1.2.3.10 , 100 , Some ISP

# Lugdunum ipfilter.srv — netmask, whitespace-separated
192.168.0.0/255.255.0.0     1       Private-Use Networks   [RFC1918]
127.0.0.0/255.0.0.0         1       Loopback               [RFC1700, page 5]

# CIDR, and a bare single address
10.0.0.0/8 , 0 , Private
203.0.113.7
```

Fields separate on commas **or** whitespace; `#`, `;` and `//` start a comment; the level
and description are both optional and a bare range defaults to level 0.

Two parsing details worth knowing, both found by testing against the *real*
`lugdunum-eserver/conf/ipfilter.srv` rather than synthetic fixtures:

- **Zero-padded octets are required.** `net.ParseIP` rejects `000.000.000.000` on Go 1.17+
  because a leading zero once meant octal, so each octet is parsed explicitly as decimal.
- **The separator cannot be chosen by "does the line contain a comma".** eserver's own
  whitespace-separated lines carry commas *inside the description* —
  `127.0.0.0/255.0.0.0   1   Loopback   [RFC1700, page 5]` — so a contains-a-comma test
  splits at `[RFC1700` and silently skips the line. The form is instead decided by which
  grammar the *address field* actually parses under.

A malformed line is counted and skipped, never treated as level 0 — level 0 is the most
aggressive setting, so guessing would block the range.

### The level threshold is inverted

A range is blocked when its level is **strictly below** `minLevel`. The convention reads
backwards: a *low* level means high confidence the range is bad, so raising `minLevel`
blocks more. 100 is eMule's default.

The threshold is applied at **load** time, not per lookup, and that is what keeps lookups
cheap: the ranges that survive are all "blocked", so overlapping and adjacent spans merge
into a disjoint sorted list and a lookup is a single binary search. Carrying levels into
the search structure would forbid merging — two overlapping ranges may disagree on level —
and force a backward scan over every candidate on the *miss* path, which is the common
path.

IPv6 is out of scope here: `ipfilter.dat` is an IPv4 format with no v6 form, so a v6 peer
is neither blocked nor allow-listed by this layer. An IPv4-mapped address is treated as
IPv4.

### Reloading

`reloadMinutes` re-reads the file on a timer so a range list can be updated without a
restart. A failed reload keeps the previous list: an operator mid-edit must not
accidentally disable filtering, and a truncated read at the wrong moment is exactly how
that would happen.

A **missing** file at startup is fatal. The operator named it, so silently serving
everyone they meant to block is the wrong failure mode.

---

## 3. GeoIP country filter

A **deny-list** of ISO 3166-1 alpha-2 codes. Deny rather than allow by decision: it is
how operators use eserver's `obfcountries` and the equivalent lists, and an allow-list on
a public eD2K server would refuse most of the network the moment a code was mistyped.
Codes are case-insensitive and whitespace-trimmed.

An address that resolves to **no** country is never blocked. The GeoLite2 database has
real gaps, and treating "unknown" as denied would silently refuse legitimate peers
whenever the database was stale or absent.

### Getting the database

The downloader is a port of `verified-gateway/pkg/geoip/download.go`, which in turn
follows MaxMind's own `geoipupdate` client.

1. Create a free MaxMind account and generate a licence key.
2. Put the credentials in `enode.local.yaml` — it is gitignored (`*.local.*`). Do **not**
   put them in `enode.config.yaml`.

```yaml
filter:
  geoip:
    enabled: true
    database: "data/GeoLite2-Country.mmdb"
    blockedCountries: ["CN", "RU"]
    accountID: "123456"
    licenseKey: "your-key-here"
    updateDays: 7
```

With both credentials present the server downloads the database on first start and
re-checks every `updateDays`. Leave **either** empty and it uses only an existing local
file and never contacts MaxMind — a half-filled config means local-only rather than
"download with a broken account", which would fail on every weekly tick.

`GeoLite2-Country`, not `GeoLite2-City`: the filter only ever needs an ISO code, and City
is an order of magnitude larger for data this server has no use for.

### Why the update is nearly free

The check is **conditional on the MD5 of the file on disk**. `client.Download(ctx,
edition, currentMD5)` returns `UpdateAvailable == false` when the server's copy matches,
so a weekly tick against an unchanged database costs one HTTP round trip and transfers
nothing. A missing file hashes to `""`, which forces the download — that contract is what
makes the first run work at all.

Two behaviours inherited from the reference implementation, both load-bearing:

- **Corrupt-file recovery.** A present-but-unopenable database is deleted before
  re-downloading. Without the delete it would hash successfully, match nothing on the
  server, be reported as "no update available", and stay corrupt forever.
- **Fail open, never fail to boot.** An absent or unreadable database with no credentials
  logs a warning and leaves country matching inactive. An access filter must not be the
  reason the server refuses to start.

One deliberate divergence from the reference: the download is written to a temporary file
and renamed into place, rather than truncating the live file with `os.Create`. A failed
transfer would otherwise leave a zero-length or half-written database that the next
startup has to detect and repair.

---

## 4. What this deliberately does not do

The Rust `ed2k-server` also carries a **behavioural** bot/scanner detector. We implement
only the static half, on purpose — the two solve different problems, and the dynamic one
is documented rather than ported. See
[`ed2k-server-rust-comparison.local.md`](ed2k-server-rust-comparison.local.md) §7.2 for
how its detector works and why a static range list cannot substitute for it: flood sources
rotate addresses, so the addresses worth banning are not knowable in advance and belong in
a time-boxed in-memory ban rather than in a hand-curated file.

Also absent: content filtering, publisher banning by user hash, and per-country welcome
messages (eserver's `welcome.xx`).

---

## 5. Operational notes

- `filter.ipfilter.file` stays in the repo root — it is operator-supplied. The GeoIP
  database lives under `data/` because the server downloads it, and `data/` is gitignored.
  Both resolve via `tests.FixRelativeTestingPath`, so a relative path means the same thing
  from any working directory.
- The startup log reports what was loaded: `ipfilter: <file> loaded, N range(s) parsed, M
  blocking, K merged, S line(s) skipped` and `geoip: <file> loaded, N denied country
  code(s)`. A large `skipped` count means the file has a line form the parser does not
  recognise; a `blocking` count far below `parsed` usually means `minLevel` is not set the
  way the operator thinks.
- `Filter.Stats()` exposes per-layer refusal counters for the admin surface.
- A sanity check that needs no MaxMind account: point `filter.ipfilter.file` at
  `lugdunum-eserver/conf/ipfilter.srv` and confirm a LAN address is refused before any
  parse on both transports.
