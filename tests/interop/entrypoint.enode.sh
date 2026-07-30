#!/bin/sh
# Renders /rig/enode.yaml.tmpl into a real config and starts the server.
#
# Why the config is rendered here rather than mounted ready-made: the container needs to
# advertise its OWN address (dynIp), and dockertest cannot assign a static IP — it builds
# an empty docker EndpointConfig, so addresses come from the network's DHCP pool and are
# only knowable once the container is up. Resolving it from inside is the one place that
# always knows. `dynIp: auto` is not an option: that probes the public internet and would
# return the host's WAN address.
#
# Environment:
#   SEED_IP        peer to bootstrap gossip from; empty means start with no seeds
#   SEED_PORT      that peer's TCP port (default 4661)
#   IPFILTER       newline-separated ipfilter.dat body; when set, the filter is enabled
#   ENODE_NAME     server name, so a multi-node test can tell the nodes apart
set -e

SELF_IP="${SELF_IP:-$(ip -4 -o addr show scope global 2>/dev/null | awk 'NR==1{split($4,a,"/"); print a[1]}')}"
SEED_PORT="${SEED_PORT:-4661}"
ENODE_NAME="${ENODE_NAME:-enode-interop}"

if [ -z "$SELF_IP" ]; then
    echo "[entrypoint] FATAL: could not determine this container's IPv4" >&2
    exit 1
fi

# Global-scope only: a ULA (fd00::/8) fails IsPublicIPv6 — Go's IsPrivate covers fc00::/7 —
# so the rig's v6 network uses 2001:db8::/32, the documentation prefix, which passes. Empty
# on a v4-only network, which renders as dynIp6: "" and simply advertises no IPv6.
SELF_IP6="${SELF_IP6:-$(ip -6 -o addr show scope global 2>/dev/null | awk 'NR==1{split($4,a,"/"); print a[1]}')}"

# A seed list of "[]" when SEED_IP is unset. The YAML is inline-flow so one sed can
# replace it without caring about indentation.
if [ -n "$SEED_IP" ]; then
    SEEDS="[{ip: \"$SEED_IP\", port: $SEED_PORT}]"
else
    SEEDS="[]"
fi

sed -e "s|__SELF_IP__|$SELF_IP|g" \
    -e "s|__SELF_IP6__|$SELF_IP6|g" \
    -e "s|__SEEDS__|$SEEDS|g" \
    -e "s|__NAME__|$ENODE_NAME|g" \
    /rig/enode.yaml.tmpl > /rig/enode.yaml

# The ipfilter body arrives as an env var rather than a mount: Docker Desktop's file
# sharing does not cover every host temp directory, and the file is three lines.
if [ -n "$IPFILTER" ]; then
    printf '%s\n' "$IPFILTER" > /rig/ipfilter.dat
    sed -i 's|__IPFILTER_ENABLED__|true|' /rig/enode.yaml
    echo "[entrypoint] ipfilter enabled:"
    sed 's/^/[entrypoint]   /' /rig/ipfilter.dat
else
    : > /rig/ipfilter.dat
    sed -i 's|__IPFILTER_ENABLED__|false|' /rig/enode.yaml
fi

echo "[entrypoint] name=$ENODE_NAME selfIP=$SELF_IP selfIP6=${SELF_IP6:-none} seeds=$SEEDS"

# Config paths in the template are relative, and enode resolves them against the module
# root when one exists — there is no go.mod in the image, so they resolve against the
# working directory instead. /rig is therefore both the config home and where data/ lands.
cd /rig
exec /usr/local/bin/enode -config /rig/enode.yaml
