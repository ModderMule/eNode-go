#!/bin/bash
set -e

# Re-creates internal/ed3k/iquic from quic-go in the module cache, with its
# crypto/tls imports pointed at the RFC 7250 fork in internal/ed3k/itls/tls.
# See docs/ed3k-tls-quic-forks.md. Run from the repository root.

QUIC_VERSION="${QUIC_VERSION:-v0.64.1}"
if [ ! -d "$PWD/internal/ed3k/iquic" ]; then
  echo "Run from the repository root."
  exit 1
fi
SRC="$(go env GOMODCACHE)/github.com/quic-go/quic-go@$QUIC_VERSION"
if [ ! -d "$SRC" ]; then
  (cd "$(mktemp -d)" && go mod download "github.com/quic-go/quic-go@$QUIC_VERSION")
fi
DST=internal/ed3k/iquic

# The packages the quic package itself builds from; http3, tests, mocks and
# tools are left out.
PKGS=". internal/ackhandler internal/congestion internal/handshake internal/monotime
internal/protocol internal/qerr internal/utils internal/utils/linkedlist
internal/utils/minheap internal/utils/ringbuffer internal/wire qlog qlogwriter
qlogwriter/jsontext quicvarint"

find "$DST" -name '*.go' -delete
for p in $PKGS; do
  mkdir -p "$DST/$p"
  for f in "$SRC/$p"/*.go; do
    case "$f" in *_test.go|*/mock_*.go|*/mockgen*.go) continue ;; esac
    head -5 "$f" | grep -q '^//go:build ignore' && continue
    cp "$f" "$DST/$p/"
    chmod u+w "$DST/$p/$(basename "$f")"
  done
done
rm -f "$DST/LICENSE"; cp "$SRC/LICENSE" "$DST/LICENSE"; chmod u+w "$DST/LICENSE"

find "$DST" -name '*.go' -exec sed -i.bak \
  -e 's#^\([[:space:]]*\)"crypto/tls"$#\1tls "enode/internal/ed3k/itls/tls"#' \
  -e 's#^import "crypto/tls"$#import tls "enode/internal/ed3k/itls/tls"#' \
  -e 's#"github.com/quic-go/quic-go#"enode/internal/ed3k/iquic#g' \
  {} \;
find "$DST" -name '*.bak' -delete
gofmt -w "$DST"
if [ -s "$DST/ed3k.patch" ]; then
  patch -s -p1 -d "$DST" < "$DST/ed3k.patch"
fi
echo "quic-go $QUIC_VERSION" > "$DST/UPSTREAM"
echo "iquic synced from quic-go $QUIC_VERSION"
