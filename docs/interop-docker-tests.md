# Interop tests against the original Lugdunum eserver

`tests/interop` runs eNode-go and the real **eserver 17.14** binary as containers on one
Docker network, so the server-to-server gossip handshake can be checked against ground
truth instead of against a reimplementation.

It exists because of a rig limitation rather than a protocol one. With eserver in a
container and eNode-go on the host, the container has **no route back**: UDP and TCP to
`192.168.65.1`, `192.168.65.254` and `host.docker.internal` are all unreachable on Docker
Desktop. So the binary could never probe us, never reached its admission test, and never
entered us in its own records — and the whole eserver→us direction was unverifiable. On a
shared network both directions are routable.

That paid for itself immediately: **three defects turned up that no unit test could have
caught**, all in §4 below.

---

## 1. Running it

```sh
ENODE_INTEGRATION=1 go test ./tests/interop/ -v -timeout 30m
```

The suite skips itself unless `ENODE_INTEGRATION=1`, matching
`storage/integration_dockertest_test.go` and the (currently commented-out) line in
`.github/workflows/linux.yml`. It skips again, with a clear message, when Docker is not
running or when `lugdunum-eserver/` is absent — that tree is gitignored, so a fresh clone
will not have it. See its `README.md` for where the binaries come from. Case E is the one
exception: it drives eNode alone, so it runs on a fresh clone with nothing but Docker.

The first run builds two images (~1 min); later runs reuse the layer cache. Expect around
3 minutes for the five cases with the images cached, most of it the two-minute propagation
timeout in §3; case E on its own is about 5 seconds.

The Docker socket is found automatically. `dockertest` only ever looks at
`/var/run/docker.sock`, which does not exist on Docker Desktop for macOS, so the rig also
tries the Desktop, Colima, Rancher and rootless locations; `DOCKER_HOST` always wins. The
client is pinned to API 1.41 because Docker Desktop answers `/_ping` at the library's
default 1.25 and then rejects `BuildImage` on it.

---

## 2. How the rig is built

| Piece | Where |
|---|---|
| eNode image (multi-stage, `CGO_ENABLED=0`) | `tests/interop/Dockerfile.enode` |
| eNode config template, rendered at container start | `enode.interop.yaml.tmpl` |
| eserver image, 32-bit under `qemu-i386` | `Dockerfile.eserver` |
| eserver config | `donkey.ini.tmpl` |
| Shared Go helpers | `rig_test.go` |
| Hand-rolled eD2K client | `client_test.go` |

Three decisions are load-bearing.

**Each container resolves its own address.** `dockertest` builds an empty
`EndpointConfig`, so it cannot pin a container IP — addresses come from the network's pool.
Both entrypoints therefore read their own interface and render their config from it. The
test only ever passes in the *peer's* address, which it already knows because that
container started first.

**The subnet is `203.0.113.0/24` (TEST-NET-3).** Docker's default `172.17/172.18` pool is
LAN under `ed2k.IsLANIP`, which would force `gossip.allowPrivatePeers: true` and exercise a
configuration no real server runs. TEST-NET-3 keeps the production default of `false`. It
is also not in eserver's own `conf/ipfilter.srv`, which blocks `172.16.0.0/10` — so a
future run with that filter loaded will not silently deny the peer. The IPv6 case uses
`2001:db8:4661::/64`: a ULA would fail `ed2k.IsPublicIPv6`, since Go's `IsPrivate` covers
`fc00::/7`, and the server would then refuse to advertise any IPv6 at all.

**eserver's console is driven through a FIFO.** Its console is on stdin and it cannot
daemonise, but `dockertest` never sets `OpenStdin`, so `docker attach` is unavailable. The
entrypoint runs `mkfifo /rig/console; sleep infinity > /rig/console & exec ./eserver <
/rig/console`, and the test writes to it with `docker exec`. Replies come back on stdout.
Three commands, found in the binary's string table, turn a five-minute test into a
forty-second one:

| Command | Effect |
|---|---|
| `ask <ip>:<port>` | force an immediate gossip round at that server |
| `saveServers` | write the peer list now, instead of on the fixed ~225 s tick |
| `vs [working]` | dump the **in-memory** server table |

One trap worth knowing if you edit `donkey.ini.tmpl`: eserver splits *every* line
containing `=` on it and does not treat `;` as a comment marker for such a line, so a
comment with an equals sign in it is parsed as a setting. Every comment in that file avoids
the character. Related, and measured: `sverbose=true` is accepted and **silently does
nothing** — it is an undocumented integer, not a boolean, and it is the flag that carries
the entire server-to-server trace. `sverbose=1` works. Everything in that file is set to
`1` for this reason.

---

## 3. The five cases

### A · `TestGossipWithLugdunumEserver` — both directions

eserver starts unseeded; eNode seeds from it; `ask` forces the reverse probe.

Our side is asserted from `/stats.json` (`gossipVerified`) and from `data/server.met`.
eserver's side is asserted from its **live table**, read with `vs`, and the row proves each
phase independently:

```
[  1]  203.0.113.3:5555 {U5567}{T5565}{Kc588ddd9}  2000[1000]/1000  0  7/0 …  enode
                        └ portUDPOBF  └ portTCPOBF  └ ServerKey                └ our name
```

`{K…}` is printed only when a ServerKey is on file, so phase 2 produced one, and `{U}`/`{T}`
are the ports we published in our `0x97`. Those three are asserted. Its log must also carry
**none** of its six refusal strings (`continue because portUDPobf`, `bad name:desc`, `sent
a bad challenge`, `from unknown server`, `ignore non obfuscated`, `Deny server`) — each
names one decision that has to be right.

The trailing `dynip=… version=… enode` can only have come from the tags in our `0xa3`, but
the *name* is **reported rather than asserted**: it survives on roughly one run in three.
Every round logs `Updating server … name= desc=` with both fields empty — its add/update
path overwriting the strings from a round that carried no tags — and a row sampled after
enough of those no longer shows a name it showed earlier. Re-issuing `ask` while polling
makes it worse, not better, so `ask` is sent once and the richest row observed is the one
kept. Phase 4 is covered instead by `servdescreply(<our ip>)` in the log.

The case then asserts eserver's own `server.met` contains us, forced with `saveServers
server.met`. That file is written only for peers it has flagged `working`, so it is the
assertion that our `ST_VERSION` tag is still clearing eserver's version gate — see §5. The
`Total : … working servers` line is logged beside it as corroboration.

Finally a client logs in over the published port and fetches `OP_SERVERLIST`, which is the
only assertion that covers the actual point of gossip: a peer learned over the wire has to
reach real clients. That client is hand-rolled from the wire format rather than built from
the server's own packet helpers — encoding a request and decoding the reply with the code
under test would let a byte-order mistake cancel itself out.

### B · `TestGossipBetweenTwoENodes` — our own protocol, dual-stack

Two eNode containers, the first unseeded. This is the **only** way to exercise the
`0xA7`/`0xA8` IPv6 extension, since eserver 17.14 predates IPv6 entirely; both ends of one
exchange are asserted. It also covers our inbound serving side and the `server.met` reload
path, by restarting a container and requiring it to seed from the persisted file.

Run this *and* case A, never one alone: with both halves ours, a symmetric bug — encoding
and decoding a field the same wrong way — passes here and fails against eserver.

### C · `TestGossipPropagatesThroughEserver` — the mesh property

enode-b registers with eserver; enode-a is seeded with eserver only and must learn b
without ever being told about it.

This was a skip until we started advertising a Lugdunum-compatible `ST_VERSION` (§5): a
peer eserver has not flagged `working` is invisible to its peer-list builder, so it sent no
list at all and there was nothing for A to learn.

Two things have to hold, and the test checks them separately so a failure says which. B
must reach eserver's `server.met` — same `working` gate, so that is the direct evidence the
version tag was accepted — and eserver must then serve B to A. Failures on our side stay
hard errors: not sending a `0xA4` is ours, and receiving a non-empty list and dropping it
is ours.

### D · `TestAccessFilterDropsEserverBeforeParsing` — the filter on a live socket

eNode starts with eserver's address in `ipfilter.dat` at level 0. Our outbound frames still
go out — we chose to initiate them, and outbound is not filtered — so eserver answers, and
every one of those answers must die at the first statement of the UDP handler.
`filterBlockedIP` climbs, `gossipVerified` stays 0, and no `server.met` is written. On the
far side eserver still *lists* us, from our own registration, but never logs
`receive cinfo from` or `servdescreply(` for us: nothing we sent was a reply.

### E · `TestVersionSurfaces` — the four version surfaces

One eNode container and no eserver, so this is the only case that runs without the vendored
binary. It pins the four places `ST_VERSION` (`0x91`) can reach a client, which deliberately
do **not** all say the same thing:

| Surface | Probe | Pinned |
|---|---|---|
| TCP `OP_SERVERMESSAGE 0x38` | log in on `5555/tcp` | `server version v0.1.0 (eNode-go)`, built from `ed2k.ENodeVersionStr` and `ed2k.ENodeName` |
| `OP_SERVERIDENT 0x41` | same connection | **no** version tag — eMule ignores one there, so we send none |
| UDP `0xa3`, challenge form | `e3 a2 <challenge:4>` to `5559/udp` | challenge echoed, `ST_VERSION` = `ed2k.GossipVersionStr` (`17.14 (eNode-go v0.1.0)`) |
| UDP `0xa3`, legacy form | `e3 a2`, under 6 bytes | name and description only: no tag block, so no version at all |

The case exists for the **guard on the first row**, which is asserted separately from the
equality so that it still fires if someone updates the expected string to match a changed
server. srchybrid runs `_stscanf("%u.%u")` over the text after `server version` and, when
that *succeeds*, reformats the whole value to a bare `%u.%02u`
(`ServerSocket.cpp:180-181`). So the tempting harmonisation — claiming
`17.14 (eNode-go v0.1.0)` on both transports — would make a real client display a plain
`17.14` with our name discarded, which is precisely what the string form of the tag was
chosen to avoid. The leading `v` is what makes that scanf fail. The test therefore fails on
any version part that parses as two dotted integers, and says why.

Its UDP probe is the only one in the package that crosses a published port rather than a
container-to-container hop, so it retries three times and its failure message separates
"no datagram came back" from "the reply was wrong". Everything is decoded by hand, as in
case A: reading a reply with the encoder under test would let a framing mistake cancel
itself out.

### What this rig cannot check — what a client *displays*

Those strings are now pinned on the wire, but *which* of them a user ends up seeing is a
client-side decision no case here can reach. Both eMule trees special-case the login line
and let it overwrite whatever the UDP tag set, so a **connected** user sees
`v0.1.0 (eNode-go)` while someone who merely holds us in a server list sees
`17.14 (eNode-go v0.1.0)` — and the client writes what it last saw into its own
`server.met` and re-shares that. srchybrid is MFC/Windows and not containerizable, so its
half stays a code read (`ServerSocket.cpp:176-183`).

**Recommended, and deliberately not built here: cover the display side in the eMuleQt repo,
<https://github.com/ModderMule/emule-qt>.** The harness already exists there —
`tests/tst_ServerLocalTest.cpp` spawns an eNode server through `SERVER_TEST_CMD` and drives
a real `ServerConnect`/`ServerList` against `127.0.0.1:5555/5565/5559/5567`, the same ports
this rig uses. Asserting `Server::version()` after login, and again after a `0xa2` desc
exchange, is a handful of lines there, needs no Docker, and lands in the tree that owns the
display logic; `tests/tst_Server.cpp` already pins tag-level version parsing. Doing it here
instead would mean a third container running the headless `emulecored` (`src/daemon`,
`docker/Dockerfile`), which drags a full Qt build and an IPC client into this loop for the
sake of one display string.

---

## 4. What the rig found

Three defects, none of which a unit test could have reached, plus one design correction.

**The obfuscated source port must be `tcp+12`, not `tcp+14`.** Two of eserver's rules have
to hold together. It skips a peer whose obfuscated frames do not arrive from the
`portUDPOBF` that peer advertised — that one was already known. But it *also* recovers a
peer's TCP port from the same source port by subtracting 12. Measured directly: a frame
from our 5567 was booked to 5555, one from 5569 to a nonexistent 5557, after which it
logged `received a pong from unknown server 203.0.113.3:5557`. Only `tcp+12` satisfies
both, so `udp.portGossip` now defaults to the obfuscated client socket and shares it.

This is one place we deliberately diverge from eserver's own configuration: it advertises
`portUDPOBF = port+14` while sending its obfuscated frames from `port+12`, so its own
advertised value and its source port disagree. We publish the port we really use.

**A gossip round must never volunteer an `OP_GLOBSERVSTATRES`.** It used to send one
whenever a peer had registered with us, echoing the challenge from that `0xA0`. A peer
keeps a *separate* per-peer ping challenge, so eserver rejected every one — `server %s:%d
sent a bad challenge %x instead of %x` — and the rejection reset its ping bookkeeping for
us. A `0x97` is only ever correct as a direct reply, because only the reply knows which
challenge was asked; the inbound handler already sends those. The unsolicited echo, and the
`TheirChallenge` state that existed only to feed it, are gone.

Note the ordering: the second bug was **masked** by the first. While our frames were being
attributed to a phantom `:5557`, the bad challenge was never even evaluated.

**The dashboard under-reported peers.** `Servers` came from `Storage.ServersCount()`, which
counts only configured entries and reads 0 for everything gossip learns. It now reports
`AdvertisedServerCount()` — the length of the list a client is actually sent — alongside
new `gossip*` and `filter*` counters, which is also what gives the tests something to poll
instead of sleeping.

---

## 5. The `working` flag, and the version tag that sets it

For a long time eserver held us in its live table — ServerKey, both obfuscation ports,
dynIP, version and name — while refusing to write us to its `server.met`, refusing to name
us to other servers, and reporting `0 working servers`.

Nothing in four minutes of `sverbose` trace explains that, because there is no rejection:
the peer is added, keyed, pinged and updated normally, and one flag stays zero.
Disassembling the binary settled it.

**eserver requires the `ST_VERSION` tag in a peer's `0xA3` name:desc reply to parse as
`>= 17.7`.** The flag that `working` depends on has exactly one writer in the binary, in
the `0xA3` handler, reached only after `sscanf(version, "%d.%d", &major, &minor)` passes
`major > 17 || (major == 17 && minor >= 7)`. The minimum minor is hard-coded at startup
and no `donkey.ini` option reaches it. We used to advertise `ENodeVersionInt = 0x00000003`,
which it renders as `0.3` — visible in the `vs` row — and `0 < 17` fails.

The same flag gates all three symptoms, and the third is why case C was a skip: eserver has
one peer-list builder, shared by `OP_SERVERLIST 0x32` for clients and `OP_SERVER_LIST_RES
0xA1` for servers, and it skips non-`working` entries. With nothing to report the `0xA1`
wrapper sends no datagram at all — which is exactly the silence case C recorded. It was
never a missing reply path.

**We now advertise `ed2k.GossipVersionStr`** — `"17.14 (eNode-go v0.1.0)"`, a *string* tag.
eserver accepts either form: the uint32 branch `sprintf`s `"%d.%d"` into a buffer that the
string branch's parse then reads, so both converge on the same `sscanf`, which stops at the
space and ignores the rest. That is what makes the string worth using — the same reply
answers *clients*, and eMule displays the tag verbatim in its server-list Version column, so
the part eserver discards is where we say who we really are. The `17.14` prefix is a
protocol-compatibility claim, not our version; the trailing part is derived from
`ENodeVersionStr`, so releases carry it (`scripts/publish-release.sh` checks that).

Measured on the rig: `0 working servers` → `1 working servers`, we appear in eserver's own
`server.met` with name and description, and case C stopped being a skip. Both interop cases
now assert eserver's `server.met` rather than reporting it, since that file has the same
`working` gate and is therefore the sharpest check that the tag is still being accepted.
`ed2k.TestServerDescResVersion` is the cheap unit-level guard, because neither side logs
anything when the bar is missed.

Two smaller findings from the same session, both worth knowing before editing the rig:

- **`saveServers` takes a filename.** Bare `saveServers` writes nothing and logs nothing;
  the argument is the `fopen` path, not the configured `autoservlist` name. Use
  `saveServers server.met`.
- **The `sping` counter is not a health probe we were failing.** It advances only when the
  ServerKey in our `0x97` differs from the one eserver already holds, and every
  registration resets it. The `7/0` reading recorded earlier was incidental; a settled row
  reads `0/0`.

The address-level derivation is in `docs/eserver-working-flag-disassembly.local.md`
(gitignored, like the binary it describes), with the raw disassembly and decompiled
functions under `lugdunum-eserver/re/`.

---

## 6. Adding a case

`rig_test.go` has the pieces: `newNetwork`, `startEserver`, `startEnode`, `node.console`,
`node.logs`, `node.stats`, `node.serverMet`, `node.restart`, `waitForStats`, `waitFor`.

Two habits matter here more than in a normal test. **Poll, never sleep-then-read** — the
console, the UDP workers and the gossip rounds all run on separate clocks, and a row that
is present is not necessarily complete: it appears at registration but only gains a name
when a later name:desc probe is answered. And **say which side a failure is about**: these
tests drive a twenty-year-old binary, so a failure message should make clear whether it is
our defect or its behaviour, as case C does.
