# Admin status dashboard

A small, self-contained HTTP status page for a running eNode server. It shows the
live server state at a glance — online clients, indexed files, LowID registrations,
advertised peer servers, uptime — alongside the server's identity, listening ports
and enabled features.

It is built with **only the Go standard library** (`net/http`, `html/template`,
`encoding/json`, `embed`) — no third-party dependencies, no external assets. The
page is a single HTML file embedded into the binary at build time
(`admin/html/dashboard.html`), so nothing needs to be deployed alongside the
executable.

## Enabling it

The dashboard is configured under the `admin` block in the YAML config:

```yaml
admin:
  enabled: true          # default on (an absent block still enables it)
  bindIP: "127.0.0.1"    # loopback only; "0.0.0.0" / "::" exposes it on all interfaces
  port: 4560             # HTTP port
  username: ""           # Basic-auth credentials for non-loopback clients;
  password: ""           # set both or neither (see "Security model")
  checkUpdates: true     # daily GitHub release check (see "Update check")
```

Defaults: **enabled**, bound to **127.0.0.1**, port **4560** (chosen to stay clear of
the eD2K ports — TCP 5555/5565, UDP 5559/5567, NAT 2004). With the block omitted
entirely the dashboard still runs on `127.0.0.1:4560`.

On startup the server logs the dashboard URL as a clickable link, or that it is off:

```
INFO  admin dashboard: http://127.0.0.1:4560/
INFO  admin dashboard: disabled
```

If `bindIP` is set to a non-loopback address and no credentials are configured, the
server additionally logs a warning that off-box clients can see the status page.

## Endpoints

| Path          | Method | Returns                                                        |
|---------------|--------|----------------------------------------------------------------|
| `/`           | GET    | The HTML dashboard (static server facts rendered server-side). |
| `/stats.json` | GET    | The live counters as JSON.                                     |
| `/accounts`   | GET    | Meta API account administration page (only with accounts on).  |
| `/api/accounts?q=&state=&offset=` | GET | Account list as JSON, 50 per page, newest first. |
| `/api/accounts/{id}` | GET | One account with its registration steps and payments.    |
| `/api/accounts/{id}/{action}` | POST | `disable`, `enable`, `adjust` (`{"days": ±N}`), `skip-step` (`{"step": "payment"}`). Returns the updated account. |
| `/api/reload-config` | POST | Re-reads the config file and applies what can change without a restart. Returns `{"applied": [...], "restartRequired": [...]}`, both lists of config key paths. |

### Reload config

The **Reload config** button in the dashboard header calls `/api/reload-config`. The
server re-reads the file it was started with and applies the changed keys below. No
listener is closed and no client is disconnected.

| Applied by a reload | |
|---|---|
| `name`, `description`, `messageLogin`, `messageLowID` | new logins and status replies use them |
| `logLevel`, `logFile` | |
| `files.softLimit`, `files.hardLimit` | |
| `tcp.loginTimeout`, `tcp.disconnectTimeout`, `tcp.connectionTimeout`, `tcp.maxConnectionsPerIP` | open connections pick up the new timeouts |
| `udp.getSources`, `udp.getFiles` | |
| `servers` | new entries only; a removed entry stays until a restart |
| `gossip.*` | including turning gossip on or off and adding seeds; the peer table is kept |
| `admin.username`, `admin.password` | |

Every other changed key is listed under `restartRequired` and keeps the value the
process started with until it is restarted. The list is repeated on each reload for as
long as the file differs from the running server.

A file that does not load, or fails validation, changes nothing: the endpoint answers
`422` with the error and the dashboard shows it.

### Account administration

With Meta API accounts enabled (see [meta-api.md](meta-api.md)) the dashboard links to
`/accounts`: search by username or email, filter by state, and open an account to see
its steps and payments (including credited and revoked times). Actions:

- **Disable / Enable.** A disabled account is refused by the API whatever its steps
  or paid period; enabling settles its state from its steps again.
- **Move access by days.** Extends (counted from the later of now and the current end)
  or shortens the paid period. Not offered for an account whose access does not expire.
- **Skip step.** Closes an open registration step without it being done, e.g. to let a
  user in without paying.

Every action is logged with the operator's address.

The page renders only the static facts (name, description, version, storage engine,
ports, feature flags). Every **dynamic** value is left as an empty placeholder that
inline JavaScript fills by polling `/stats.json` — on first paint and every 5
seconds — so the numbers stay current without a full reload, and no live figure is
ever baked into the served HTML.

`/stats.json` shape:

```json
{
  "clients": 0,
  "files": 0,
  "lowIDs": 0,
  "servers": 0,
  "uptimeSeconds": 6,
  "time": "2026-07-22T15:00:49+07:00",
  "gossipKnown": 0,
  "gossipVerified": 0,
  "gossipParked": 0,
  "gossipAdmitted": 0,
  "gossipRejectedBad": 0,
  "gossipRejectedSelf": 0,
  "gossipRejectedClient": 0,
  "gossipRejectedFull": 0,
  "gossipRejectedUnsolicited": 0,
  "gossipRejectedPlaintext": 0
}
```

The `gossip*` fields are explained in `server-gossip.md` §5; the response carries
further sections (filters, meta search, update check) not shown here.

The client and file totals come from the same briefly cached reading that backs the
eD2K `OP_SERVERSTATUS` / `OP_GLOBSERVSTATRES` responses (see `ed2k/countercache.go`),
so a dashboard left open polling every few seconds cannot turn into a flood of
`COUNT(*)` queries against the storage backend.

## Update check

With `admin.checkUpdates` on (the default) the server looks up the latest published
release once a day, starting about 30 s after startup. It sends one `HEAD` request to
`https://github.com/ModderMule/eNode-go/releases/latest` and does not follow the
redirect. GitHub answers with a 302 whose `Location` is the release page:

```
HTTP/2 302
location: https://github.com/ModderMule/eNode-go/releases/tag/v0.3.3
```

The tag is the last path segment. Nothing is parsed from a body, and api.github.com
and its rate limit are not involved. Only a `Location` of exactly
`https://github.com/ModderMule/eNode-go/releases/tag/vX.Y.Z` is accepted, and that URL
is the link the dashboard shows. Draft and pre-release entries never count as "latest",
so the CI draft releases are announced only once they have been published.

The result is served as `update` in `/stats.json`
(`{"latest","url","available","checkedAt"}`, or `null` when the check is off or has not
succeeded yet). A failed check keeps the previous result. The page shows
`· update available: vX.Y.Z` (a link) next to the version when GitHub has a newer
release, and a muted `(latest)` when this build is current. A newer release is also
logged once per check at INFO.

Set `checkUpdates: false` if the server must never contact github.com.

## Security model

The dashboard is **loopback-only by default**. Access rules (`admin/auth.go`):

| Client | Credentials configured | Status page, `/stats.json` | Accounts pages and API, config reload |
|---|---|---|---|
| loopback (and no proxy header) | either | yes, no login | yes, no login |
| anyone else | no | yes (as before) | **403** |
| anyone else | yes | Basic auth | Basic auth |

- A request that reached loopback **through a proxy** (`X-Forwarded-For`, `Forwarded`,
  `X-Real-IP`, `X-Forwarded-Host`) is *not* treated as local, so a reverse proxy on the
  same machine cannot open the dashboard to the internet by accident.
- Non-loopback requests are rate-limited (120 per minute per address) and failed logins
  are logged. Credentials are compared in constant time. Basic auth sends the password
  with every request: expose the dashboard only over TLS (a reverse proxy, or an SSH
  tunnel).
- State-changing requests must carry `X-Enode-Admin: 1` and, when the browser sends an
  `Origin`, come from the dashboard's own origin. A cross-site page cannot set that
  header, so even the login-free loopback case is safe from CSRF.

## Quick check

```bash
go run ./cmd/enode -config enode.local.yaml
# then, from the same machine:
curl -s localhost:4560/stats.json
open http://localhost:4560/          # or visit it in a browser
```
