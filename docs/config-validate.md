# Validating a config

```sh
./enode -validate -config enode-bang.local.yaml
```

Checks the file and exits: status 0 when there are no errors, 1 otherwise. It binds no
socket, opens no database and makes no network call, so it is safe to run next to a
live server (e.g. before `update.sh` or a SIGHUP reload).

Each finding is printed as `error` or `warning`:

- **error**: the server would refuse to start, or a setting cannot work.
- **warning**: the server starts, but a key is ignored or probably not what was meant.

## What is checked

| Area | Check |
|---|---|
| YAML | unknown keys (a typo otherwise loads silently as the zero value) |
| Load | everything `config.Load` checks at startup (handoff mode, admin credentials, metaApi, serverSearch, ...) |
| `logLevel` | a known level |
| `address` | an IP literal; an IPv4 bind with `ipv6.enabled` warns: the listeners are then IPv4 only |
| `dynIp` | `auto`, empty, or a public IPv4 (the IPv6 belongs in `ipv6.dynIp6`) |
| `ipv6.dynIp6` | `auto`, empty, or a public IPv6; warns when advertised but nothing listens on IPv6 |
| `ipv6.address` | warns: parsed, but no listener reads it; the top-level `address` decides the bind |
| `ed3k.advertise*` | IP literals of the right family |
| Ports | two enabled listeners on the same TCP or UDP port; `udp.port` = tcp+4 and `udp.portObfuscated` = tcp+12, which eMule hardwires |
| `servers` | IPv4 or public IPv6, a port, no duplicates |
| Misc | retired `natTraversal.serverIndependent`, legacy `udp.serverKey`, admin on a non-loopback bind without credentials |
