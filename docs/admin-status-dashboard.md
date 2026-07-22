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
```

Defaults: **enabled**, bound to **127.0.0.1**, port **4560** (chosen to stay clear of
the eD2K ports — TCP 5555/5565, UDP 5559/5567, NAT 2004). With the block omitted
entirely the dashboard still runs on `127.0.0.1:4560`.

On startup the server logs the dashboard URL as a clickable link, or that it is off:

```
INFO  admin dashboard: http://127.0.0.1:4560/
INFO  admin dashboard: disabled
```

If `bindIP` is set to a non-loopback address, the server additionally logs a warning
that the page is reachable off-box.

## Endpoints

| Path          | Method | Returns                                                        |
|---------------|--------|----------------------------------------------------------------|
| `/`           | GET    | The HTML dashboard (static server facts rendered server-side). |
| `/stats.json` | GET    | The live counters as JSON.                                     |

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
  "time": "2026-07-22T15:00:49+07:00"
}
```

The client and file totals come from the same briefly cached reading that backs the
eD2K `OP_SERVERSTATUS` / `OP_GLOBSERVSTATRES` responses (see `ed2k/countercache.go`),
so a dashboard left open polling every few seconds cannot turn into a flood of
`COUNT(*)` queries against the storage backend.

## Security model

The dashboard is **loopback-only by default** and has **no authentication**. This is
intentional for the common case (an operator inspecting a server from the same
machine, e.g. over an SSH tunnel). Binding it to a non-loopback address publishes an
unauthenticated status page — only do so behind your own access control (a reverse
proxy with auth, a firewall, a VPN).

> ToDo (tracked in `admin.New`): add an optional token / basic-auth gate before a
> non-loopback bind is documented as a supported configuration.

## Quick check

```bash
go run ./cmd/enode -config enode.local.yaml
# then, from the same machine:
curl -s localhost:4560/stats.json
open http://localhost:4560/          # or visit it in a browser
```
