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
will not have it. See its `README.md` for where the binaries come from.

The first run builds two images (~1 min); later runs reuse the layer cache. Expect around
3½ minutes for the four cases, most of it the two-minute propagation timeout in §3.

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

## 3. The four cases

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
it is **reported rather than asserted**: it survives on roughly one run in three. Every
round logs `Updating server … name= desc=` with both fields empty, and a row sampled after
enough of those no longer shows a name it showed earlier. Re-issuing `ask` while polling
makes it worse, not better — it drives more of those updates — so `ask` is sent once and the
richest row observed is the one kept. Phase 4 is covered instead by `servdescreply(<our
ip>)` in the log, which records the probe being answered rather than what eserver did with
the answer. Same bookkeeping unreliability as §5.

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

### C · `TestGossipPropagatesThroughEserver` — skipped, with a finding

enode-b registers with eserver; enode-a is seeded with eserver only and should learn b.
**It does not**, and the test ends in `t.Skip` carrying the evidence rather than a failure.

The test distinguishes the two possible causes rather than leaving it to the reader. Not
sending a `0xA4` request would be our failure and is a hard error. Receiving a non-empty
list and dropping it would also be ours, and is a hard error. What actually happens is that
we ask repeatedly and eserver **never answers at all**, while its own table demonstrably
holds both nodes — so it is the reference implementation's behaviour, and consistent with
§5 below.

It is kept as a skip rather than deleted: if this ever starts working, the test says so.

### D · `TestAccessFilterDropsEserverBeforeParsing` — the filter on a live socket

eNode starts with eserver's address in `ipfilter.dat` at level 0. Our outbound frames still
go out — we chose to initiate them, and outbound is not filtered — so eserver answers, and
every one of those answers must die at the first statement of the UDP handler.
`filterBlockedIP` climbs, `gossipVerified` stays 0, and no `server.met` is written. On the
far side eserver still *lists* us, from our own registration, but never logs
`receive cinfo from` or `servdescreply(` for us: nothing we sent was a reply.

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

## 5. Known gap: eserver's bookkeeping about us is unreliable

eserver holds us in its live table with our ServerKey, both obfuscation ports, our dynIP,
version and name. It does **not** write us to its `server.met`, and does not name us to
other servers. Both follow from one thing: it reports `0 working servers`, and the manual
says `autoservlist` records "only working known servers".

What was tried, and did not move it: correcting the source port (which did advance its ping
counters from `0/0` to `7/0`), removing the unsolicited `0x97`, forcing rounds with `ask`,
waiting four minutes, and giving our side a logged-in client with a published file so our
advertised counts were non-zero. Across all of it the row froze after an initial burst and
its counters never moved again.

The name it holds for us behaves the same way: it arrives, appears in the row, and is gone
again after a few rounds, each of which logs `Updating server … name= desc=` empty.

`working` is an internal heuristic of a closed-source 2007 binary and we cannot currently
drive it. The tests therefore assert the parts of its live table that are stable on every
run — the ServerKey and both obfuscation ports, which are what prove our phases completed —
and *report* the parts that are not: the name, and whether we made it into `server.met`.
Making a run fail on a flag we do not understand would be asserting something we cannot
explain, and would leave a suite that fails two runs in three for reasons outside this
codebase.

None of this affects a client: what a client receives is `OP_SERVERLIST`, which case A
asserts directly.

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
