# Bot detection

eNode lists the addresses whose UDP searches and source requests look automated. It
**only observes**: nothing is banned or dropped because of it. A listed address stays
subject to `udp.rateLimitPerIPPerMinute` like any other, and the operator decides what
to do — typically nothing, or a ban from the admin dashboard.

The list is the **Bots** tab of the [admin dashboard](admin-status-dashboard.md)
(`GET /api/bots`). Each detection is also logged once as a warning.

## What is watched

Every UDP request that the per-address rate limit covers: global searches
(`OP_GLOBSEARCHREQ` and its extended forms) and source requests (`OP_GLOBGETSOURCES`
and its extended forms). Status pings and TCP traffic are not counted.

The detector sees a request **before** the rate limiter does. With the default limit
of 120 requests a minute the limiter would otherwise hide every rate above its own
budget, and no address could ever reach the thresholds below.

A source is the address the rate limiter buckets on: an IPv4 address, or the /64 of an
IPv6 one. A flood spread over one IPv6 prefix is therefore one source.

## When an address is listed

Each source has a sliding 60-second window of its request times.

1. Fewer than 30 requests in the window: not judged.
2. A rate below `minQueriesPerMinute` (default 200): not listed. A real client sends a
   server one global search and about one source request a minute.
3. A rate above `floodQueriesPerMinute` (default 600): listed as a **flood**.
4. Otherwise, when the gaps between its requests have a standard deviation below
   `maxIntervalStddevMs` (default 50 ms): listed for **uniform timing**. A person, and
   a client acting for one, is far less regular than that.

A listed source is measured again at most every 30 seconds, which is also how often
its "flagged" count can rise. A detection stays on the list for 24 hours after it was
last seen and is gone after a restart.

The list shows, per source: country (with `filter.geoip`), the rate and the gap
deviation at the last detection, the reason, how often it was flagged, and when it was
first and last seen.

## Configuration

```yaml
udp:
  botDetection:
    enabled: true
    minQueriesPerMinute: 200
    floodQueriesPerMinute: 600
    maxIntervalStddevMs: 50
```

`floodQueriesPerMinute` must not be below `minQueriesPerMinute`. The section is applied
by a config reload; the list is kept. With `enabled: false` nothing is recorded and the
Bots tab is not shown.

## Cost and limits

- A request below the thresholds costs one map lookup and one append under a mutex.
  The deviation is only computed for a source already above `minQueriesPerMinute`, and
  then at most once per 30 seconds.
- One source can make the detector remember at most 4096 request times (32 KiB), and
  at most 100,000 sources are tracked. UDP source addresses can be forged, so without
  that bound a spoofed flood would grow the table without limit. Sources idle for a
  minute are forgotten.
- For the same reason a listed address is not proof: a forged source address can put
  somebody else's address on the list. That is why detection does not ban.

## Origin

The rules are those of the Rust `ed2k-server`'s bot detector, which additionally bans a
flagged source for 24 hours by dropping its UDP datagrams before parsing. eNode leaves
that step out.
