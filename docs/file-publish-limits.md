# Per-client file publish limits (`softLimit` / `hardLimit`)

How many files a single client may publish to this server, and what happens when it tries
to publish more. Both limits are configured under `files:` in `enode.config.yaml`,
enforced per TCP session, and advertised on the wire so a client sees the numbers it is
actually held to.

For what a given cap costs in RAM at scale, see [`memory-footprint.md`](memory-footprint.md) §4.

## 1. What the two limits are

They are **per-client publish caps**, not statements about server capacity — a point worth
making because the field names in `OP_GLOBSERVSTATRES` sit next to `maxusers` and read like
capacity figures. Both come from Lugdunum's eserver, whose documentation is vendored in
this repo at [`lugdunum-eserver/docs/kiten-20071012.txt`](../lugdunum-eserver/docs/kiten-20071012.txt):

> **`softLimit`** (`:462`) — *"If a client tries to publish more than softLimit files, the
> server sends him a WARNING message and ignores files in excess. Default value : 1000"*

> **`hardLimit`** (`:349`) — *"If a client tries to publish more than hardLimit files, the
> server disconnects him (before receiving the whole list). That is to save bandwidth,
> because some lazy people share all their files. Default value : 4000"*

So the hard limit is not simply a larger soft limit; the two exist for different reasons.

| | soft limit | hard limit |
|---|---|---|
| **What it is** | a quota on the index | an abuse response |
| **What it protects** | server RAM — how large the file index grows | server bandwidth — receiving a huge list at all |
| **Effect** | excess records are ignored; the client stays connected and keeps working | the session is closed |
| **Client is told** | one `WARNING` `OP_SERVERMESSAGE` per session | one `ERROR` message, then the close (see §5) |
| **eserver default** | 1000 | 4000 |
| **eNode-go default** | 10000 | 20000 |

eserver's own accounting reflects the split: it reports both in its live stats line
(`eserver-17.14-strings.txt:20339`, `…:softLimit=%u:hardLimit=%u:…`) but counts hard-limit
drops with the *refusals*, alongside blacklisting and ipfilter, in its console counter
(`:20958` — `%lu blacklisted, %lu ipfilter, %lu full, … %lu hardlimit, …`).

## 2. Why the count is cumulative, not per packet

Neither cap can be applied to a single `OP_OFFERFILES` frame, because no frame is ever big
enough to trip one. eMule caps a packet at 200 files regardless of the server's limit:

```cpp
uint32 limit = pCurServer ? pCurServer->GetSoftFiles() : 0;
if (limit == 0 || limit > 200)
    limit = 200;
```
— `srchybrid/SharedFileList.cpp:832-834`, mirrored by `eMuleQt/src/core/files/SharedFileList.cpp:639-643`
with `kMaxOfferedFiles = 200`. A server's soft limit can only *lower* that number.

The remainder arrives in later packets: `Process()` re-calls `SendListToServer()` every
`ED2KREPUBLISHTIME` (60 s — `srchybrid/SharedFileList.cpp:1229-1236`, `kEd2kRepublishSecs`
in eMuleQt) until the whole share is registered. A client sharing 5,000 files therefore
takes ~25 minutes to publish it all, 200 at a time.

So eNode-go counts **across every offer of one TCP session**. Lugdunum's "before receiving
the whole list" describes the old single-huge-frame clients (early eDonkey, mldonkey);
against a modern client the same rule has to be applied cumulatively or it never fires.

### Records, not distinct hashes

The counter counts *records received*, not distinct file hashes. This is a deliberate
divergence from eserver, which limits rows in its store.

It is safe for the clients that matter, because both eMule trees send each shared file
exactly once per server session. `SendListToServer()` selects only files where
`!cur_file->GetPublishedED2K()` and marks each one published as it goes
(`srchybrid/SharedFileList.cpp:817,848`), and `ClearED2KPublishInfo()` — which resets those
flags — runs only on connect and on disconnect (`ServerConnect.cpp:227-228,292,340,438`),
never on a timer. For a conforming client, "records received" and "distinct files" are the
same number.

The alternative, a per-session set of published hashes, was rejected on cost: at a hard
limit of 20,000 that is ~320 KiB per session, which across the session counts
[`memory-footprint.md`](memory-footprint.md) §4.2 plans for is larger than the index it
would be protecting. A third-party client that re-offers its whole list inside one session
would be over-counted; none of the clients this server targets does that.

## 3. Configuration

```yaml
files:
  softLimit: 10000   # warn once, ignore the excess; 0 = unlimited
  hardLimit: 20000   # message, then disconnect; 0 = unlimited
```

- **`0` means unlimited** on either key, the same convention `tcp.maxConnections` uses.
- **An absent key** uses the default shown above (`config.DefaultSoftFileLimit` /
  `DefaultHardFileLimit`). The fields are `*int` precisely so an explicit `0` can be told
  from an omitted key — with a plain `int`, an operator writing `0` for "unlimited" would
  silently get the default instead.
- **`hardLimit` below `softLimit` is rejected at load.** The two are checked hard-first per
  record, so the session would be closed before the soft warning could ever be sent: the
  operator would have written a soft limit that can never fire, with nothing to tell them.
  `hardLimit == softLimit` is allowed — it collapses to "drop at N", which is coherent.
- The defaults are **not** eserver's 1000/4000. They are the values eNode-go has advertised
  since it was written, kept so that enabling enforcement changes behaviour without also
  changing what clients are told. An operator wanting eserver's posture sets 1000/4000.

## 4. On the wire

Both values are published at `OP_GLOBSERVSTATRES` (0x97) payload offsets **+16** and **+20**
(`ed2k/udpoperations.go`, `BuildGlobServStatResPacket`). eMule reads them positionally
(`srchybrid/UDPSocket.cpp:337-342`, stored at `:403-404`; eMuleQt
`src/core/server/ServerList.cpp:848-849,893-896`) and persists them in `server.met` as the
tags `ST_SOFTFILES 0x88` / `ST_HARDFILES 0x89` (`srchybrid/Opcodes.h:309-310`,
`eMuleQt/src/core/utils/Opcodes.h:371-372`), written back only when non-zero.

The advertised values and the enforced values come from the same two config keys, resolved
through the same accessors in `cmd/enode/main.go`. Advertising a cap that is not applied is
the state this feature exists to end.

### What clients do with them

- **`softFiles`** is used: it clamps the per-packet offer count, as shown in §2. That is
  its only behavioural use anywhere in either tree.
- **`hardFiles` is never used for anything.** Grep both clients and every reference is
  store, persist, or display — the server list column, the "Soft/Hard File Limits" line in
  the network-info dialog, the web server, the IPC layer. No arithmetic, no comparison, no
  throttling. It is the server's business alone, which is why §5 matters.

## 5. What a client sees

**Soft limit.** One `OP_SERVERMESSAGE`, sent the first time the session goes over and never
again:

```
WARNING : This server accepts 10000 shares per client. Some of your shares are ignored.
```

That is eserver's own text, verbatim (`eserver-17.14-strings.txt:20786`). The `WARNING`
prefix is load-bearing rather than cosmetic: both clients divert a server message beginning
with it to the warning log instead of the server-info pane
(`srchybrid/ServerSocket.cpp:195-201`, `eMuleQt/src/core/server/ServerConnect.cpp:1208-1210`).
Nothing else in either client reacts — the clamp reads `softFiles` from `server.met` and the
UDP stat, not from this text, so the client keeps publishing at the same rate and the server
keeps ignoring the excess.

**Hard limit.** One message, then the close:

```
ERROR : This server accepts at most 20000 shares per client. Closing the connection.
```

This is our **one deliberate divergence from eserver**, which drops silently: the 17.14
strings carry an operator-overridable `MsgSOFTLIMIT` keyword with no `MsgHARDLIMIT`
counterpart. Sending nothing is defensible for a server that also keeps a `hardlimit`
reject counter an operator can read — but a client cannot distinguish a silent drop from
any other mid-session close, so the user has no way to learn why they keep getting
disconnected. Neither client has any handling for this case; it takes its generic reconnect
path either way.

The message reaches the client before the FIN: nothing in this server sets `SetLinger`, so
Go's default graceful close flushes the socket buffer. Same ordering as the duplicate-login
path, which is known to work against real clients.

Server-side, the drop is logged and the session's close reason is `file-hard-limit`:

```
WARN  offer files hard limit remote=203.0.113.7 id=2570397 offered=20001 hardLimit=20000: closing
INFO  tcp session closed remote=203.0.113.7 reason=file-hard-limit
```

## 6. Behaviour worth knowing

- **Which files survive the soft trim** is "whichever arrived first", and that is the right
  answer rather than an accident: eMule sorts its offer by upload priority before
  truncating to the packet cap (`srchybrid/SharedFileList.cpp:814-828`), so the files that
  survive the server's cap are the client's own highest-priority share.
- **Anything the soft limit skips is gone for the rest of that session**, even if capacity
  frees up later, because the client has already marked those files published and will not
  re-offer them. This is exactly eserver's stated semantics — "ignores files in excess" —
  and should not be "fixed" with a retry.
- **The counter never decreases**, including when `CleanupStale` drops a file the session
  published. Both limits are defined against what a client *tries to publish*, not against
  what the index currently holds. (A live session's rows are never swept anyway: the MySQL
  sweep is `online = 0 AND time_offer < ?`, and the memory sweep only drops zero-source
  files.)
- **A reconnect resets the counter**, so a determined client can re-publish past the soft
  limit by cycling the connection. This is left alone deliberately. On the memory engine
  `Disconnect` deletes that client's source entries outright, so both sides restart from
  zero together and nothing compounds. On MySQL and MongoDB the rows survive until
  `CleanupStale` expires them, but `Connect` is keyed on the user hash and returns the same
  `StoreID`, and `AddFile` upserts — so a plain reconnect-and-republish revives the
  identical rows. The only real bypass is a client that *shuffles which files it publishes
  first* on each cycle, which costs it a full login per `hardLimit` files and which no
  per-session design can stop. Guarding it would need a hash-keyed counter with a TTL.
- **A large sharer will be dropped on a cycle.** With the defaults, a client sharing 50,000
  files reaches 20,000 records at packet 101 — about 100 minutes into the session — is
  dropped, reconnects, and is dropped again ~100 minutes later, indefinitely. This is
  faithful to eserver (which does the same at 4,000/200 ≈ 20 minutes) but it is a behaviour
  change for anyone upgrading an existing eNode-go deployment, where nothing was enforced.
  Raise `hardLimit`, or set it to `0`, to keep the old behaviour.
- **Offers are not gated on login.** `OP_OFFERFILES` is dispatched whether or not the
  session has logged in — pre-existing behaviour, unchanged here. The counter is per
  connection, so the limits apply to a pre-login offer exactly as they do to any other.

## 7. Where the code is

| What | Where |
|---|---|
| Config keys, defaults, validation | `config/config.go` — `FilesConfig`, `setDefaults` |
| Enforcement | `ed2k/server_runtime.go` — `handleOfferFiles`, and the `offeredFiles` / `softLimitWarned` / `hardLimitHit` fields on `tcpClient` |
| Message texts | `ed2k/server_runtime.go` — `msgSoftFileLimit`, `msgHardFileLimit` |
| Advertising | `ed2k/udpoperations.go` — `BuildGlobServStatResPacket`, `UDPConfig.SoftFiles/HardFiles` |
| Wiring | `cmd/enode/main.go` — both runtime configs, from one accessor each |
| Tests | `ed2k/offer_limits_test.go`, `config/file_limits_test.go` |
