#!/bin/bash
set -e

# Re-creates internal/ed3k/itls/tls from the installed Go toolchain's crypto/tls
# and applies the RFC 7250 raw-public-key patch (rpk.patch). See docs/ed3k-tls-quic-forks.md.
#
# Run from the repository root after a Go upgrade, then run the itls and ed3k
# tests. A patch that no longer applies is resolved by hand and rpk.patch is
# regenerated with: git diff --no-index <pristine copy> internal/ed3k/itls/tls

if [ ! -d "$PWD/internal/ed3k/itls" ]; then
  echo "Run from the repository root."
  exit 1
fi

GOROOT_SRC="$(go env GOROOT)/src"
DST=internal/ed3k/itls/tls
SHIM=enode/internal/ed3k/itls/shim

rm -f "$DST"/*.go
for f in "$GOROOT_SRC"/crypto/tls/*.go; do
  case "$f" in *_test.go) continue ;; esac
  cp "$f" "$DST/"
done
# BoringCrypto defaults and the cert generator are not built here.
rm -f "$DST/defaults_boring.go" "$DST/generate_cert.go"

for f in "$DST"/*.go; do
  sed -i.bak \
    -e "s#\"crypto/internal/boring\"#\"$SHIM/boring\"#" \
    -e '/fipsaes "crypto\/internal\/fips140\/aes"/d' \
    -e "s#\"crypto/internal/fips140/aes/gcm\"#\"$SHIM/gcm\"#" \
    -e 's#aes\.(\*fipsaes\.Block)#aes#g' \
    -e "s#\"crypto/internal/fips140/tls12\"#\"$SHIM/tls12\"#" \
    -e "s#\"crypto/internal/fips140/tls13\"#\"$SHIM/tls13\"#" \
    -e "s#\"crypto/tls/internal/fips140tls\"#\"$SHIM/fips140tls\"#" \
    -e "s#\"internal/byteorder\"#\"$SHIM/byteorder\"#" \
    -e "s#\"internal/cpu\"#\"$SHIM/cpu\"#" \
    -e "s#\"internal/godebug\"#\"$SHIM/godebug\"#" \
    -e '/^\/\/go:linkname /d' \
    "$f"
  rm -f "$f.bak"
done
gofmt -w "$DST"

patch -s -p1 -d "$DST" < internal/ed3k/itls/rpk.patch
go version > internal/ed3k/itls/UPSTREAM
echo "itls synced from $(cat internal/ed3k/itls/UPSTREAM)"
