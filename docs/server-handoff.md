# Restarting without dropping clients (handover)

A restart used to disconnect every client. eMule then reconnects to whichever server is
first in its priority-sorted list (`srchybrid/ServerConnect.cpp`, `CS_DISCONNECTED` →
`ConnectToAnyServer()`), which is often not this one. Clients that do come back
re-publish their whole share list and lose the search they were running.

A **handover** avoids that. The running server starts its successor (normally a new
binary at the same path) and passes it every listening socket, every TCP session and the
storage state those sessions need. The successor carries on serving them, and the old
process exits. Clients see a pause of a few tens of milliseconds and nothing else: no
disconnect, no new login, no re-publish. Obfuscated sessions continue at the exact byte
of their RC4 keystream.

Linux and macOS only. Windows cannot pass sockets between processes, so a restart there
drops the connections as before.

---

## Triggering one

| How | What happens |
|---|---|
| `scripts/update.sh` | Installs the new release. If an enode from that directory is running, sends it SIGUSR2 and waits for the successor, instead of starting a second server. |
| `kill -USR2 <pid>` | Hands over to whatever binary is now at the path the server was started from, or to the same binary if nothing changed. |
| systemd `ExecReload` | `systemctl reload enode` with the unit below. |

The pid is in `pidFile` (default `data/enode.pid`), which the server writes once it
serves. The successor rewrites it with its own pid. A clean stop removes it.

The successor runs detached from the terminal, so Ctrl+C no longer stops it: use `kill $(cat data/enode.pid)`.

```yaml
pidFile: "data/enode.pid"
```

`update.sh` takes the file's location from `pidFile` in the config file: the one named
by `-config` among its arguments, else `enode.config.yaml` in its install directory.
Without that key it uses `data/enode.pid`, and `ENODE_PIDFILE` overrides all of these.
Relative paths resolve against the install directory. Before signalling, it checks that the pid belongs
to a process named `enode`, because SIGUSR2 kills a process that does not handle it,
including an enode older than this feature. Those older versions write no pid file, so
they are never signalled. `ENODE_NO_HANDOFF=1` skips the handover, and
`ENODE_HANDOFF_WAIT` (default 900 s) bounds how long the script waits for one.

A handover that is refused or fails leaves its reason in `<pidFile>.handoff`
(`data/enode.pid.handoff`). `update.sh` removes that file before signalling and reports
it as soon as it appears, instead of waiting out `ENODE_HANDOFF_WAIT`. The old server is
then still running the previous version, and the script says so.

The successor gets the predecessor's command line without `-daemon` (it is started
detached anyway) and without `-reindex-manticore` (which would rebuild the index on every
handover). It reads the config file again, so config changes take effect. Ports that
changed are bound fresh, and inherited sockets the new config does not use are closed.

### systemd

With the default `Type=simple`, systemd treats the old process's exit as the service
stopping and kills the successor along with it. Let the successor announce itself
instead:

```ini
[Service]
Type=notify
NotifyAccess=all
ExecStart=/opt/enode/enode -config /opt/enode/enode.config.yaml
ExecReload=/bin/kill -USR2 $MAINPID
```

The server sends `READY=1` once it serves. A successor sends `MAINPID=<its pid>` and
`READY=1` once it has taken over, so systemd follows the service to the new process. If
`NOTIFY_SOCKET` is not set, none of this is sent.

---

## Sequence

```
 predecessor (serving)                         successor
 ─────────────────────                         ─────────
 SIGUSR2
 spawn bootExecutable, passing:
   control lane, descriptor lane, every
   listening socket (TCP, UDP, admin, Meta API,
   server search)                       ──────▶ boots with all gates closed:
 keeps serving meanwhile                        adopts the inherited sockets as it binds,
                                                accepts nothing, reads no UDP
                                        ◀────── READY (protocol version)
 close the TCP gate (accept nothing)
 park every session at its next read
 ── clients paused from here ──
 export sessions, then storage          ──────▶ import storage
 send session states, then their sockets ─────▶ rebuild sessions (LowIDs, hash index)
                                        ◀────── IMPORTED
 COMMIT                                 ──────▶ start sessions, open the gates
 ── clients served again ──
 close its copies of the sockets and exit
```

Before READY, the predecessor serves normally. That covers however long the successor
takes to boot: resolving `dynIp`, loading GeoIP, setting up Manticore. The pause clients
see runs from parking to commit. The end-to-end test measures about 65 ms on macOS and
240 ms in a Linux container.

### Parking

A session parks at its next read. The read loop checks for a handover before each read,
and `ParkSessions` keeps setting a past read deadline on any session that has not parked
yet, which interrupts a read that is blocked. A session busy in a handler parks when the
handler returns, for example a login waiting on its dial-back probe, or an offer being
written to a slow database.

A session that has not parked after 15 s is closed and released as if it had
disconnected. Its client reconnects, as every client did on a restart before.

Once a session is parked, its write lock is held, so nothing writes to it: not the status
ticker, and not a peer's `OP_CALLBACKREQUEST`. Its state can then be read out without
moving its RC4 keystream. On commit the predecessor keeps those locks until it exits. On
abort it releases them.

### What a session carries

`ed2k.SessionState` (gob):

- **Obfuscation:** the state machine, the pending handshake bytes, and both RC4 keys with
  their positions.
- **A half-received packet:** a partial header, or a header with part of its payload.
- **Identity:** login state, `ClientInfo` (ID, StoreID, hash, ports, IPv6), LowID flag,
  nick, software, mod, connect time, IPv6 and meta capabilities.
- **Session-local state:** the pending search page for `OP_QUERY_MORE_RESULT` (with a
  fresh `tcp.moreResults.ttlSeconds` deadline in the successor), the
  soft-limit warning latch, and the hard-limit, login-gate and ban-list latches with
  their hit sets.

Bytes the predecessor had not read yet stay in the kernel's socket buffer, and the
successor reads them. Its first `OP_SERVERSTATUS` comes one status interval after the
handover.

### Storage

| Engine | What crosses | Successor's `Init` |
|---|---|---|
| `memory` | Everything: files (including those with no source), every source in offer order, the clients with their StoreIDs, and the StoreID counter. Streamed from the predecessor under its read lock. | `LoadSnapshot` is skipped: the handover is newer and has the sources a snapshot lacks. |
| `mysql`, `mongodb` | Only the per-session offered counts that `files.softLimit` is checked against. The rows stay in the database. | Does not reset the online flags (`storage.Config.KeepOnline`). The rows belong to live sessions. |
| + `manticore` | Whatever the wrapped engine sends. The index holds nothing per session. | As the wrapped engine. |

The predecessor skips its shutdown snapshot after a handover, because the successor now
writes the snapshots.

A successor configured with a different storage engine refuses the stream, and the
predecessor resumes serving.

### The memory engine: `handoff.memory`

With the `memory` engine the whole index crosses, and this key decides how. The database
engines ignore it.

```yaml
handoff:
  memory: "stream"   # stream | file | off
```

| Value | How the index moves | Peak RAM | Pause |
|---|---|---|---|
| `stream` (default) | Over the control lane, straight into the successor. | Both processes hold the index: about twice the index. | Shortest |
| `file` | Written to `storage.snapshot.file` + `.handoff` (`data/storage.gob.handoff`), then dropped from the predecessor and its memory returned to the system, and only then read by the successor. The predecessor removes the file once the handover is committed. | About one index: the two never hold it at once. | Longer: a write and a read of the file. Needs the disk space. |
| `off` | No handover. SIGUSR2 is refused and the reason written to the status file, so `update.sh` reports it and leaves the old server running. | — | — |

`file` is for a host whose RAM holds one index but not two. It is not the snapshot
format: a snapshot leaves out the sources and the clients (see
[storage-snapshot.md](storage-snapshot.md)), and a handover needs both. The handover file
is written only for the handover, uncompressed, and next to the snapshot file because
that is where the operator has already made room for an index on disk. Snapshots do not
need to be enabled.

While the index is out in the file, the predecessor holds none of it. TCP sessions are
parked, but UDP searches and source requests reaching the predecessor in that window
are answered from an empty index, as they would be just after a restart. A periodic
snapshot in that window writes nothing and leaves the file on disk as it was. If the
handover fails, the predecessor reads the file back before it resumes the sessions.

The key is read from the config file when SIGUSR2 arrives, so one handover can use
another mode without a restart. If the file no longer loads, the value from boot applies.

Measured on Linux (`golang:1.26` container) with 2 million files and no sessions:

| | Predecessor before | Lowest predecessor during | Both processes, peak | Successor after | Pause |
|---|---|---|---|---|---|
| `stream` | 1879 MiB | 1530 MiB | 2763 MiB | 1016 MiB | 3.3 s |
| `file` | 1849 MiB | 50 MiB | 2287 MiB | 1016 MiB | 4.1 s |

In `file` mode the peak is the predecessor on its own, before it lets go, and the
successor then grows into the memory it freed. The predecessor is larger than the
successor holding the same index, because a Go heap carries headroom over what it holds.
macOS keeps counting freed memory in a process's RSS until the system needs it, so the
drop shows there only under memory pressure; the log line `heap in use … → … MiB` shows
it either way.

The pause grows with the index. With the memory engine, clients wait about 1.5 to 2 s
per million files, against tens of milliseconds for a small index or a database engine.

---

## What does not move

All of this is soft state that rebuilds itself:

- **PR_NAT registrations.** Clients re-register on their next keepalive cycle. Until then,
  a LowID↔LowID rendezvous for them fails as it would for an unregistered client.
- **The gossip peer table.** The successor reads `server.met` at boot, so it misses peers
  learned since the last persist.
- **Spam-detector observations of current sessions.** Its verdict log persists.
- **Rate limiters, the UDP bot detector, admin counters and uptime, meta-search caches.**
  All start from zero.
- **In-flight HTTP requests** on the admin dashboard, Meta API or server search. Both
  processes serve those sockets until the old one exits, so a request still running in
  the old process when it exits is cut off.
- **`MaxConnections`.** Sessions taken over are not counted against the listener's
  `maxConnections` in the successor. They are counted for `maxConnsPerIP`.

UDP needs no handover. Both processes read the shared sockets until the predecessor
exits. The successor reads none before commit.

---

## When it fails

The predecessor never stops serving because of a failed handover:

| Failure | Outcome |
|---|---|
| `handoff.memory: off` with the memory engine | Refused before anything starts. |
| Successor fails to start, crashes while booting, or is not ready within 5 min | Killed; predecessor goes on serving. Logged as `handoff failed, still serving`. |
| Successor speaks another handover protocol version | Refused before anything parks; restart the old way. |
| Storage export or import fails, or the transfer takes over 10 min | Successor killed; with `handoff.memory: file` the index is read back from the file; parked sessions resume; TCP gate reopens. |
| Predecessor vanishes before COMMIT | Successor exits without serving anything. It never serves a socket the predecessor may have gone back to. |
| A session does not park within 15 s | That session is dropped and its client reconnects; the rest move. |

Every row here also writes its reason to `<pidFile>.handoff`. SIGUSR2 can be sent again
after a failure.

---

## Protocol

`internal/handoff`. The successor receives these descriptors and finds them through
the `ENODE_HANDOFF` environment variable (JSON), which it removes once read:

- **fd 3, control lane.** A stream socket carrying `[kind u8][len u32 BE][payload]`
  frames. The storage export travels as `MsgData` chunks ending with `MsgDataEnd`.
- **fd 4, descriptor lane.** Each message carries one byte of data plus up to 64 socket
  descriptors (`SCM_RIGHTS`). The receiver reads with a one-byte buffer, so a read never
  spans two messages and no descriptor can be matched to the wrong session. Sessions
  arrive on the control lane in the same order as their sockets on this lane.
- **fd 5+, listening sockets.** Keyed by `network + " " + address`, exactly as the
  binding code asks for them (`handoff.Listen`, `handoff.ListenUDP`), so an unchanged
  config adopts each one.

`ProtocolVersion` changes only when this sequence changes. Session and storage states are
gob, so fields can be added to or removed from them between versions without a bump.

Two things matter when passing sockets:

- **Never call `File.Fd()` on a socket that is still being served.** It switches the
  socket to blocking mode, and that mode is shared by every duplicate, so the
  connection's deadlines stop working. The lane gets descriptors through `SyscallConn`
  instead.
- `os/exec` does call `Fd()` on `ExtraFiles`, so `Spawn` switches every registered socket
  back to non-blocking mode after starting the successor.

## Tests

- `internal/handoff`: socket adoption, frames, the data stream and 67 sockets across the
  lanes, sockets staying non-blocking, and both sides of the protocol for success, a
  failed import, a protocol version mismatch and a missing commit.
- `storage`: memory engine round trip (order, offered lists, complete flags, files with
  no source, the StoreID counter), offered counts for the database engines,
  pass-through for Manticore, and refusal of another engine's stream. Through a file:
  the predecessor is emptied, the successor gets what a stream gives, an abort reads the
  index back and removes the file, a failed write keeps the index, and a snapshot taken
  meanwhile keeps the file on disk.
- `config`: `handoff.memory` values and the handoff file's path. `cmd/enode`: which mode
  applies to which engine, and the fallback to the boot config.
- `ed2k`: an obfuscated LowID session and a plaintext HighID session move between two
  runtimes, each with half a packet in flight, then complete it, get their sources, and
  route a callback. Also: resume after an abort, and stragglers being dropped.
- `cmd/enode` (skipped with `-short`): builds the binary and hands a live client over
  twice, the second time after the binary was replaced the way `update.sh` replaces it.
  The same once with `handoff.memory: file`. With `off`, SIGUSR2 leaves the reason in
  the status file and the server keeps serving the same socket. Run it on Linux too, for
  example in `golang:1.26`.
- `cmd/enode` with `ENODE_INTEGRATION=1`: the same two handovers on the `mysql` engine,
  against the MariaDB of `scripts/docker-mariadb.sh` (port 13306, or
  `ENODE_TEST_MYSQL_PORT`), and on the `mongodb` engine, against the MongoDB of
  `scripts/docker-mongodb.sh` (port 37017, or `ENODE_TEST_MONGODB_PORT`). Each is
  skipped when nothing listens on its port.
