#!/bin/bash
set -e

# Regenerates ed3k/ed3kpb from the ed3k spec's normative proto (Protocol.md §0).
#
# The spec file is copied verbatim into ed3k/proto/ed3k.proto with one added line,
# the go_package option, so the checked-in copy shows exactly what was generated
# from. The generated code is checked in; nobody needs protoc to build eNode-go.
# Run this only after the spec's proto changed.
#
# ED3K_SPEC points at the spec checkout (default: the eMuleQt submodule beside
# this repository's usual location).

if [ ! -d "$PWD/scripts" ]; then
  echo "Please run this shell script from the repository's root folder."
  exit 1
fi

PROTOC_GEN_GO_VERSION="v1.36.11"
ED3K_SPEC="${ED3K_SPEC:-$HOME/Documents/Coding/CPP/eMuleQt/docs/ed3k-spec}"
TOOLS_DIR="$PWD/bin/tools"

command -v protoc >/dev/null 2>&1 || {
  echo "protoc is not installed. On macOS: brew install protobuf"
  exit 1
}
[ -f "$ED3K_SPEC/proto/ed3k.proto" ] || {
  echo "ed3k spec not found at $ED3K_SPEC (set ED3K_SPEC)"
  exit 1
}

mkdir -p "$TOOLS_DIR" ed3k/proto ed3k/ed3kpb
GOBIN="$TOOLS_DIR" go install "google.golang.org/protobuf/cmd/protoc-gen-go@${PROTOC_GEN_GO_VERSION}"

# Copy, adding go_package right after the package line.
awk '{ print } /^package ed3k\.v1;/ { print ""; print "option go_package = \"enode/ed3k/ed3kpb\";" }' \
  "$ED3K_SPEC/proto/ed3k.proto" > ed3k/proto/ed3k.proto
echo "spec: $(git -C "$ED3K_SPEC" rev-parse --short HEAD 2>/dev/null || echo unknown)"

rm -f ed3k/ed3kpb/*.pb.go
PATH="$TOOLS_DIR:$PATH" protoc -I ed3k/proto \
  --go_out=ed3k/ed3kpb --go_opt=paths=source_relative \
  ed3k/proto/ed3k.proto
echo "Done."
