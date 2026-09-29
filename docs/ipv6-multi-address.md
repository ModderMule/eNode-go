# IPv6 on hosts with several addresses

A server commonly has more than one global IPv6 on the same interface: a stable
address (static, DHCPv6, EUI-64 or stable-privacy SLAAC) plus one or more temporary
privacy addresses (RFC 8981) that rotate daily and expire within a week. Two things
depend on which one eNode-go uses.

## Which address is advertised (`ipv6.dynIp6`)

| `dynIp6` | Advertised address |
|----------|--------------------|
| `""` | none, no IPv6 self-advertisement |
| a literal | exactly that address |
| `"auto"` | see below |

With `auto`, the server first asks the `testUrls6` echo endpoints what address they
see. That is the source the kernel chose for the outbound connection (RFC 6724), and
with privacy extensions enabled it is usually a **temporary** address. The answer is
then checked against the host's own addresses and their state:

1. The probed address is local and stable: it is used.
2. The probed address is not local (NPTv6, NAT66, a tunnel): it is used as-is.
3. The probed address is local but temporary, deprecated or tentative: a stable
   local address is used instead, preferring one in the same /64. The log says so:
   `dynIp6 resolved: … (via=… (replaced temporary X with stable Y))`.
4. Every probe failed: the first stable local address is used.

If only unstable addresses exist, one is used and a warning says it will rotate
away. If more than one stable address exists, the log names the one advertised.
In either case, set `dynIp6` to the address you want (the one in your DNS AAAA
record) to take the choice out of the server's hands.

The address is resolved once at startup.

Address state is read from rtnetlink on Linux, `GetAdaptersAddresses` on Windows and
`SIOCGIFAFLAG_IN6` on macOS. Other platforms have no state, so every address counts
as stable, which is how the server behaved before this check existed.

## Which address UDP replies come from

The listeners bind the dual-stack wildcard, so TCP and UDP are reachable on every
address. TCP always answers from the address the client connected to. With UDP the
kernel picks a source for every send unless told otherwise, so a reply could leave
from an address the client never contacted. The client, or its stateful firewall,
then drops it.

On a wildcard dual-stack bind, the UDP listeners now record each datagram's arrival
address (`IPV6_RECVPKTINFO`). IPv6 replies are sent from that address. PR_NAT
forwards to the *other* peer of a pairing are sent from the IPv6 announced in the
v6 REGISTER ack. IPv4 traffic is unchanged.

Windows has no control-message support in `golang.org/x/net/ipv6`, so there the
kernel still picks the source. Binding `ipv6.address` to a single address avoids the
problem on any platform.

Server-to-server gossip starts its own sends, so there is no arrival address to reply
from, and those still use the kernel's source (a ToDo in `ed2k/gossipclient.go`).
