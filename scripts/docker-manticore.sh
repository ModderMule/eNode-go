#!/bin/bash
set -e

# Spin up a throwaway Manticore Search for local testing of storage.manticore.
# The container is ephemeral (--rm, no data volume): every start is an empty
# index. The server creates its table on first connect (storage.ManticoreEngine)
# and its startup reconcile pass fills it from the mysql or mongodb database, so
# nothing is lost but the time the pass takes.
#
# eNode talks to it over the MySQL protocol; 9308 is its HTTP JSON API, useful
# for poking at the index by hand.

if [ ! -d "$PWD/scripts" ]; then
  echo "Please run this shell script from the project's root folder."
  exit 0
fi

MANTICORE_SQL_PORT=19306
MANTICORE_HTTP_PORT=19308

case "$1" in
  stop)
    docker stop enode_manticore 2>/dev/null || true
    echo "Manticore has been stopped."
    ;;
  *)
    docker run --rm -d \
      -p ${MANTICORE_SQL_PORT}:9306 \
      -p ${MANTICORE_HTTP_PORT}:9308 \
      --name enode_manticore \
      manticoresearch/manticore:latest

    echo "Manticore is running on localhost:${MANTICORE_SQL_PORT} (SQL) and ${MANTICORE_HTTP_PORT} (HTTP)."
    echo "storage.manticore.dsn: \"tcp(127.0.0.1:${MANTICORE_SQL_PORT})/\""
    echo "A shell into it: docker exec -it enode_manticore mysql -P9306 -h0"
    ;;
esac
