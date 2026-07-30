#!/bin/sh
# Renders donkey.ini, opens the console on a FIFO, and starts eserver under qemu-i386.
#
# Environment:
#   THIS_IP    address to advertise; "auto" (the default) resolves the container interface
#   SEED_IP    another server to bootstrap a peer list from
#   SEED_PORT  that server's TCP port (default 4661)
#   IPFILTER   newline-separated ipfilter.srv body; loaded as the server-range filter
set -e

cd /eserver

THIS_IP="${THIS_IP:-auto}"
if [ "$THIS_IP" = "auto" ]; then
    THIS_IP="$(ip -4 -o addr show scope global | awk 'NR==1{split($4,a,"/"); print a[1]}')"
fi
if [ -z "$THIS_IP" ]; then
    echo "[entrypoint] FATAL: could not determine this container's IPv4" >&2
    exit 1
fi

sed -e "s|__THIS_IP__|$THIS_IP|g" donkey.ini.tmpl > donkey.ini

# seedIP is honoured only when no serverList.met is present or it is empty (per the
# manual), which is the state of a fresh container. Note the asymmetric filenames: eserver
# READS serverList.met and WRITES the autoservlist file, so its own output never disables
# the seed.
if [ -n "$SEED_IP" ]; then
    printf 'seedIP=%s\nseedPort=%s\n' "$SEED_IP" "${SEED_PORT:-5555}" >> donkey.ini
    echo "[entrypoint] seedIP=$SEED_IP seedPort=${SEED_PORT:-5555}"
fi

if [ -n "$IPFILTER" ]; then
    printf '%s\n' "$IPFILTER" > /eserver/ipfilter.srv
    echo "[entrypoint] ipfilter.srv written:"
    sed 's/^/[entrypoint]   /' /eserver/ipfilter.srv
fi

# The console is on stdin and eserver cannot daemonise, but dockertest never sets
# OpenStdin on the container, so `docker attach` is unavailable. A FIFO gives the test a
# writable console anyway: `docker exec ... echo <cmd> > /rig/console`. The three commands
# that matter are `ask <ip>:<port>` (force an immediate gossip round), `saveServers`
# (write the peer list now instead of on the ~225s tick) and `vs` (dump the in-memory
# server table). Replies land on stdout, where `docker logs` picks them up.
#
# `sleep infinity` holds the write end open — without a writer the FIFO would deliver EOF
# and eserver would treat it as the console closing.
mkdir -p /rig
rm -f /rig/console
mkfifo /rig/console
sleep infinity > /rig/console &

echo "[entrypoint] thisIP=$THIS_IP — console FIFO at /rig/console"

# Raise the fd ceiling the way upstream's script.sh does.
ulimit -n 65536 2>/dev/null || true

exec qemu-i386-static ./eserver < /rig/console
