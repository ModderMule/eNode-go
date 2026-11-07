# Hosts with several addresses (IPv6, and IPv4 for several servers)

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
v6 REGISTER ack. On Linux, IPv4 is pinned too; see the next section.

Windows has no control-message support in `golang.org/x/net/ipv6`, so there the
kernel still picks the source. Binding `ipv6.address` to a single address avoids the
problem on any platform.

Server-to-server gossip starts its own sends, so there is no arrival address to reply
from. Its IPv6 frames leave from `SelfIPv6` (the advertised IPv6) when a local
interface holds it, else from the kernel's source (`sendFromSelf` in
`ed2k/gossipclient.go`).

## Several servers on one host, each on its own IPv4

Two instances on one machine, each with its own IPv4 and `address: ""` (for example
bang on 176.116.0.51 and razor on 176.116.0.62), listen on every address. Unpinned,
everything either one sends over IPv4 UDP leaves from the route's preferred source
(`ip -4 route get 1.1.1.1` shows it as `src`), which is the same address for both.
For the instance that does not own it:

- peers key servers by source IP, so its gossip is filed under the other server and
  it is never listed;
- eMule drops a status reply from an IP it did not ping, so the server looks dead;
- the TCP dial-back of a HighID check comes from the wrong IP, which eMule holds back
  (`AwaitingTestFromIP`), so clients get a LowID.

On Linux the server now pins the IPv4 source as well:

| Send | IPv4 source |
|------|-------------|
| UDP reply to a datagram | the address the datagram arrived on |
| UDP send that answers nothing (gossip, PR_NAT forwards) | the advertised IP (`dynIp`), when a local interface holds it; logged at startup as `udp: IPv4 sends leave from …` |
| TCP dial-back (HighID check) | the address the client's own connection arrived on |

The UDP source is set with `IP_PKTINFO`, which Linux accepts on the v4-mapped sends
of a dual-stack socket. If the kernel refuses a pinned send (the address left the
interface), it goes out unpinned. Behind 1:1 NAT the advertised IP is not local, so
the server keeps the kernel's choice; replies are still pinned to the arrival address.

Other platforms keep the kernel's choice for IPv4. There, set `address` to the
instance's IPv4 (the listeners then bind IPv4 only), or rewrite the source with an
`iptables -t nat ... -m owner --uid-owner <user> -j SNAT` rule.
