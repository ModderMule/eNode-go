# Admin dashboard

A small, self-contained HTTP admin page for a running eNode server. Its first tab,
**Status**, shows the live server state at a glance — online clients, indexed files,
LowID registrations, advertised peer servers, uptime — alongside the server's identity,
listening ports and enabled features. The other tabs list the connected clients, the
shared files, the peer servers, the filters, bans, automated queriers, refusals, data
files and recent warnings, the Go runtime, Meta API accounts and the effective
configuration. See [Tabs](#tabs).

It is built with **only the Go standard library** (`net/http`, `html/template`,
`encoding/json`, `embed`) — no third-party dependencies, no external assets. The page
is embedded into the binary at build time: `admin/html/dashboard.html` is the shell and
the Status tab, and each further tab is one file under `admin/html/tabs/`. Nothing
needs to be deployed alongside the executable.

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
the eD2K ports — TCP 5555/5565, UDP 5559/5567/5569, NAT 2004). With the block omitted
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
| `/accounts`   | GET    | Redirects to the Accounts tab, `/#accounts` (only with accounts on). |
| `/api/accounts?q=&state=&offset=` | GET | Account list as JSON, 50 per page, newest first. |
| `/api/accounts/{id}` | GET | One account with its registration steps and payments.    |
| `/api/accounts/{id}/{action}` | POST | `disable`, `enable`, `adjust` (`{"days": ±N}`), `skip-step` (`{"step": "payment"}`). Returns the updated account. |
| `/api/reload-config` | POST | Re-reads the config file and applies what can change without a restart. Returns `{"applied": [...], "restartRequired": [...]}`, both lists of config key paths. |

The tabs beyond Status have their own endpoints, listed under [Tabs](#tabs).

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
| `udp.botDetection.*` | the list of flagged addresses is kept |
| `servers` | new entries only; a removed entry stays until a restart |
| `gossip.*` | including turning gossip on or off and adding seeds; the peer table is kept |
| `admin.username`, `admin.password` | |

Every other changed key is listed under `restartRequired` and keeps the value the
process started with until it is restarted. The list is repeated on each reload for as
long as the file differs from the running server.

A file that does not load, or fails validation, changes nothing: the endpoint answers
`422` with the error and the dashboard shows it.

### Account administration

With Meta API accounts enabled (see [meta-api.md](meta-api.md)) the dashboard has an
**Accounts** tab: search by username or email, filter by state, and open an account to see
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

`/stats.json` is the operator's view and is not meant to be public: it needs a login
from off-box once credentials are set. A public liveness probe and a public status
route with the advertised figures only are served by the Meta API HTTP listener
(`GET /healthz`, `GET /status`); see [meta-api.md](meta-api.md#health-and-status).

`clients` and `files` are read from storage at most once every
`storage.countCacheSeconds` (default 60, read at startup) and shared with the
status packets. `files` is the engine's estimate: exact on the memory engine,
InnoDB's row estimate on mysql/mariadb and the collection's metadata count on
mongodb. On mysql/mariadb it can differ from `SELECT COUNT(*) FROM files` by tens
of percent and moves in steps when InnoDB recalculates its statistics; counting
exactly would scan the whole table on every refresh.

The `gossip*` fields are explained in `server-gossip.md` §5; the response carries
further sections (filters, meta search, update check) not shown here.

Each entry of the `meta` array, one per enabled meta search network, carries the
daemon's estimate of its whole network next to its catalogue figures:
`networkUsers`, `networkUsersExperimental` and `networkFiles`, 0 when the daemon has
none. They are shown as reported, whether or not `statsBoost` adds the users to the
advertised count; see [meta-search.md](meta-search.md#network-estimates).

A daemon that counts the users it has seen over time adds `networkUsersSeen` and
`networkUsersSeenDay`, with `networkUsersSeenWindow` (the window in seconds) and
`networkUsersSeenSince` (RFC 3339, when it began counting). A window of 0 is a daemon
that does not count them, and the Network row then shows the estimates alone.

With server-to-server search on, `serverSearch` carries its figures and the page shows a
**Server search** section: the mode (`allowlist` or `gossip`), the listener URL and the
certificate fingerprint to hand to peers, what was served to other servers (`searches`,
`browses`, `filesServed`, `resets`) and refused (`authFailures`, `rateLimited`), whether
this server asks its peers (`liveSearch`, `mirror`, `mirrorFiles` of `mirrorMaxFiles`),
and a `peers` array with one entry per server it asks: `url`, `static` (configured, as
opposed to found through gossip), the peer's own `name` and `files`, `down` and
`lastError`, the mirror state (`mirrored`, `mirrorFiles`, `mirrorAt`, `mirrorTrimmed`,
`walks`, `walkErrors`, `resets`) and the live-search counters. The field is `null` when
the service is off. See [server-search.md](server-search.md).

The client and file totals come from the same briefly cached reading that backs the
eD2K `OP_SERVERSTATUS` / `OP_GLOBSERVSTATRES` responses (see `ed2k/countercache.go`),
so a dashboard left open polling every few seconds cannot turn into a flood of
`COUNT(*)` queries against the storage backend.

## Tabs

The tab bar sits under the header. The address keeps the open tab (`/#clients`), so a
reload or a bookmark returns to it. The page polls `/stats.json` every 5 seconds for
the header and the Status tab, and additionally only the tab that is open; Files,
Accounts and Config load when opened and on demand. Every value a tab shows is inserted
as text, never as markup: nicks, file names and peer descriptions are other people's
strings.

A tab is shown only when the server has the feature: **Bans** needs the content filter
(any of `filter.keywords`, `filter.hashBanlist`, `filter.hashFilter`,
`filter.hashWhitelist`), **Bots** needs `udp.botDetection.enabled`, **Accounts** needs
Meta API accounts.

| Tab | Shows | Endpoints |
|---|---|---|
| Status | the page described above | `GET /stats.json` |
| Clients | software and country distribution; the connected clients with address, country, software, nick, published files, High/Low ID, IPv6 and connected time. Filtered, sorted and paged by the server. | `GET /api/clients?q=&country=&software=&id=high\|low&sort=&dir=&offset=&limit=`, `GET /api/clients/summary` |
| Files | the shared file index: browse, or search file names; click a file for its sources | `GET /api/files?q=&cursor=&limit=`, `GET /api/files/{hash}/sources` |
| Peers | the gossip peer table (name, address, users, files, state, last seen, who told us) and the static server list | `GET /api/peers` |
| Filter | what the IP filter, the country filter and the content filter have loaded and refused; their data files | `GET /api/filter` |
| Bans | the user hashes and addresses refused at login, with their expiry | `GET /api/bans` |
| Bots | addresses whose UDP queries look automated; see [bot-detection.md](bot-detection.md) | `GET /api/bots` |
| Blocks | how often each kind of refusal happened since the start | `GET /api/blocks` |
| Health | the filters' data files (present, size, age, entries) and the last 100 warnings and errors | `GET /api/health` |
| Runtime | Go heap, goroutines, garbage collection, heap per indexed file, storage settings | `GET /api/runtime` |
| Accounts | Meta API accounts; see [Account administration](#account-administration) | `/api/accounts…` |
| Config | the effective configuration, secrets hidden | `GET /api/config` |

Notes on what the tabs read:

- **Clients.** `q` matches a substring of the address, nick, IPv6 address or user hash,
  or an IPv4 CIDR (`82.48.0.0/16`). `limit` is at most 500. Nick and software are what
  the client sent at login (`CT_NAME`, `CT_EMULE_VERSION`); country needs
  `filter.geoip` with a loaded database.
- **Files.** Files the content filter withholds are not listed. A search returns its
  whole capped answer at once; browsing pages through the files that have a source
  online, with an opaque cursor.
- **Peers.** A peer's server key and challenges are never part of the answer.
- **Runtime.** The memory figures are read at most every 10 seconds, because reading
  them briefly stops the Go runtime.
- **Health.** The log is kept in memory (the last 200 warnings and errors) and starts
  empty after a restart.

### Actions

The dashboard can change a running server in these ways, and no others. Each is a
`POST` or `DELETE`, needs the write header (see [Security model](#security-model)) and
is logged with the operator's address.

| Action | Endpoint | Effect |
|---|---|---|
| Disconnect a client | `POST /api/clients/{hash}/disconnect` | closes that session. The client can log in again at once; ban it to prevent that. |
| Ban | `POST /api/bans` with `{"key": "ip:203.0.113.9", "minutes": 1440}` | refuses that address or user hash (`hash:<32 hex digits>`) at login for the given time. An IPv6 address is banned as its /64. A client that is already connected stays until it is disconnected. |
| Lift a ban | `DELETE /api/bans/{key}` | |
| Add a server | `POST /api/servers` with `{"ip": "203.0.113.5", "port": 4661}` | adds an entry to the static server list sent to clients |
| Remove a server | `DELETE /api/servers/{ip}/{port}` | removes one |
| Reload filter files | `POST /api/filter/reload` | re-reads the IP filter, the hash lists and the country database from disk now |
| Update hash lists | `POST /api/filter/update` | fetches the hash lists from the update service now |
| Reload config | `POST /api/reload-config` | see [Reload config](#reload-config) |
| Account actions | `POST /api/accounts/{id}/{action}` | see [Account administration](#account-administration) |

- Bans are the content filter's publisher bans (see [access-filters.md](access-filters.md)):
  kept in memory, gone after a restart, and only available with the content filter on.
- A server added or removed here lasts until the next restart or config reload, which
  applies the `servers:` list of the config file again.
- **Reload filter files** is offered only when a filter that reads a file is enabled
  (`filter.ipfilter`, `filter.geoip`, or one of the hash lists), and **Update hash
  lists** only with `filter.update.enabled`. Without them the buttons are not rendered
  and the endpoints answer `404`.

### Configuration view

The Config tab shows the configuration in effect — the file, with defaults filled in
and reloadable keys as the last reload left them — as YAML. It cannot be edited there:
change the file and reload or restart.

Secrets never leave the process. A secret that is set is shown as `(set, hidden)`, an
unset one as empty:

- `admin.username`, `admin.password`
- `udp.serverKey`
- `filter.geoip.accountID`, `filter.geoip.licenseKey`
- `metaSearch.*.token`, `serverSearch.peers[].token`
- `metaApi.tls.keyFile`, `serverSearch.tls.keyFile`
- `storage.mysql.host`, `user`, `pass`; `storage.mongodb.host`, `uri`
- a `metaApi.accounts.steps[]` entry keeps only its `id`, `type` and `enabled`: the rest
  is the step's own settings, which for a payment step are API credentials.

`statsBoost` is left out entirely. A test (`config/redact_test.go`) fails when a new
config key whose name reads like a secret is not on the list.

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

| Client | Credentials configured | Status tab, `/stats.json` | Every other tab, its API and every action |
|---|---|---|---|
| loopback (and no proxy header) | either | yes, no login | yes, no login |
| anyone else | no | yes | **403** |
| anyone else | yes | Basic auth | Basic auth |

Without credentials a visitor from another machine still gets the page and sees the
Status tab; the other tabs show that they need loopback access or credentials. Client
addresses, file names, the log and the configuration are only ever served to loopback
or to a logged-in operator.

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
