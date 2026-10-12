#!/bin/sh
# Measures how much memory the original Lugdunum eserver holds per indexed file.
#
# Starts a fresh eserver in Docker, reads the empty baseline, publishes FILES files from
# CLIENTS connected clients over the wire, waits for the server to settle, reads it again
# and removes everything. The workload is the one tests/membench and the Rust server's
# examples/loadgen.rs use, so the three results compare directly.
#
# usage: run.sh <files> <clients> [tag]
#
# Environment:
#   ENODE_INTEROP_ESERVER  17.14 or 17.15 (default 17.15), as in the Go interop suite
#   LUGMEM_SETTLE          seconds to wait after the last publish (default 120)
#   LUGMEM_CONCURRENCY     clients logging in at once (default 32)
#   LUGMEM_VERBOSE         1 turns the eserver trace on; only for small runs (default 0)
#   LUGMEM_KEEP            1 leaves the containers and network up for inspection
#
# Output lands in out/<tag>/: measure-baseline.txt, measure-loaded.txt, status.json,
# loader.log and server.log. See docs/interop-docker-tests.md.
set -e

FILES=$1
CLIENTS=$2
if [ -z "$FILES" ] || [ -z "$CLIENTS" ]; then
    echo "usage: $0 <files> <clients> [tag]" >&2
    exit 2
fi
TAG=${3:-f$FILES-c$CLIENTS}
VERSION=${ENODE_INTEROP_ESERVER:-17.15}
SETTLE=${LUGMEM_SETTLE:-120}
CONC=${LUGMEM_CONCURRENCY:-32}
VERBOSE=${LUGMEM_VERBOSE:-0}

D=$(cd "$(dirname "$0")" && pwd)
RIG=$(cd "$D/.." && pwd)
REPO=$(cd "$D/../../.." && pwd)
OUT=$D/out/$TAG

# The same two binaries rig_test.go knows.
case "$VERSION" in
    17.14) BIN=$REPO/lugdunum-eserver/run/eserver-17.14.i686-linux.nptl ;;
    17.15) BIN=$REPO/lugdunum-eserver/bin/eserver-17.15.i686-linux ;;
    *) echo "unknown ENODE_INTEROP_ESERVER $VERSION" >&2; exit 2 ;;
esac
if [ ! -f "$BIN" ]; then
    echo "$BIN is missing: the gitignored lugdunum-eserver/ tree is not present" >&2
    exit 1
fi

NET=lugmem-net
SERVER=lugmem-server
LOADER=lugmem-loader
SERVER_IP=10.77.0.2

cleanup() {
    if [ "${LUGMEM_KEEP:-0}" = "1" ]; then
        return
    fi
    docker rm -f $SERVER $LOADER >/dev/null 2>&1 || true
    docker network rm $NET >/dev/null 2>&1 || true
    rm -rf "$CTX"
}

# Snapshot of the server's own stats, the qemu process and the container.
measure() {
    F=$OUT/measure-$1.txt
    {
        echo "### $(date -u +%FT%TZ) tag=$TAG label=$1 eserver=$VERSION"
        echo "## nbuser (TCP 5656)"
        if docker ps --format '{{.Names}}' | grep -q "^$LOADER\$"; then
            docker exec $LOADER python3 /loader/stats.py $SERVER_IP
        else
            docker run --rm --network $NET --entrypoint python3 lugmem-loader /loader/stats.py $SERVER_IP
        fi
        echo "## /proc/1 (qemu-i386-static) status"
        docker exec $SERVER sh -c 'grep -E "^(VmPeak|VmSize|VmHWM|VmRSS|RssAnon|RssFile|RssShmem|VmData|VmSwap|Threads)" /proc/1/status; echo "## smaps_rollup"; cat /proc/1/smaps_rollup; echo "## cgroup memory"; cat /sys/fs/cgroup/memory.current 2>/dev/null; grep -E "^(anon|file|kernel|sock|slab) " /sys/fs/cgroup/memory.stat 2>/dev/null'
        echo "## docker stats"
        docker stats --no-stream --format '{{.Name}} mem={{.MemUsage}} cpu={{.CPUPerc}}' $SERVER
        echo "## console: stats, slab, debug"
        N=$(docker logs $SERVER 2>&1 | wc -l)
        docker exec $SERVER sh -c 'for c in stats slab debug; do echo $c > /rig/console; sleep 3; done'
        docker logs $SERVER 2>&1 | tail -n +$((N + 1))
    } > "$F" 2>&1
    echo "--- $1"
    grep -E "^users=|VmRSS|VmHWM|mem=" "$F" | cut -c1-200
}

rm -rf "$OUT"
mkdir -p "$OUT"

# The server image reuses the interop rig's Dockerfile and entrypoint unchanged. Only the
# donkey.ini differs, and the binary comes from the gitignored tree, so the context is
# staged in a temp directory the way rig_test.go does it.
CTX=$(mktemp -d)
trap cleanup EXIT
cp "$RIG/Dockerfile.eserver" "$CTX/Dockerfile"
cp "$RIG/entrypoint.eserver.sh" "$CTX/entrypoint.eserver.sh"
cp "$BIN" "$CTX/eserver.i686"
sed -e "s|__VERBOSE__|$VERBOSE|g" "$D/donkey.ini.tmpl" > "$CTX/donkey.ini.tmpl"
docker build -q -t lugmem-eserver:$VERSION "$CTX" >/dev/null
docker build -q -t lugmem-loader -f "$D/Dockerfile.loader" "$D" >/dev/null

docker rm -f $SERVER $LOADER >/dev/null 2>&1 || true
docker network rm $NET >/dev/null 2>&1 || true
# A /16 because the loader puts every client on its own address, 10.77.16.1 upward.
docker network create --subnet 10.77.0.0/16 $NET >/dev/null

docker run -d --name $SERVER --network $NET --ip $SERVER_IP \
    --ulimit nofile=65536:65536 lugmem-eserver:$VERSION >/dev/null
sleep 20
measure baseline

docker run -d --name $LOADER --network $NET --ip 10.77.0.3 --cap-add NET_ADMIN \
    --ulimit nofile=65536:65536 -v "$OUT":/out lugmem-loader loader.py $SERVER_IP \
    --files "$FILES" --clients "$CLIENTS" --concurrency "$CONC" >/dev/null

# status.json is rewritten every two seconds; wait until every client has published or
# the loader has died.
while :; do
    sleep 5
    if ! docker ps --format '{{.Names}}' | grep -q "^$LOADER\$"; then
        echo "loader exited early:" >&2
        docker logs --tail 20 $LOADER >&2 || true
        exit 1
    fi
    DONE=$(python3 -c 'import json,sys
try:
    s = json.load(open(sys.argv[1]))
    print(1 if s["published"] + s["failed"] >= s["target_clients"] else 0)
except Exception:
    print(0)' "$OUT/status.json")
    if [ "$DONE" = "1" ]; then
        break
    fi
done

echo "published, settling for ${SETTLE}s"
sleep "$SETTLE"
measure loaded

docker logs $LOADER > "$OUT/loader.log" 2>&1 || true
docker logs $SERVER > "$OUT/server.log" 2>&1 || true
echo "--- loader"
cat "$OUT/status.json"
echo
echo "raw output in $OUT"
