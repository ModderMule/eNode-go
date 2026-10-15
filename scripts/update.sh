#!/usr/bin/env bash
set -euo pipefail

# Self-updater for an installed eNode-go release bundle.
#
# Detects the OS/arch, downloads the matching bundle of the latest published
# GitHub release, verifies its .sha256, installs it over the directory this
# script lives in, and starts enode.
#
# The script ships inside every bundle and as a standalone release asset, so a
# fresh install can bootstrap with:
#
#   curl -fLO https://github.com/ModderMule/eNode-go/releases/latest/download/update.sh
#   bash update.sh
#
# Usage: ./update.sh [enode arguments...]
#
#   Every argument is handed to enode unchanged when it is started, e.g.
#     ./update.sh -daemon                      start in the background
#     ./update.sh -config config.yaml -daemon  use another config file
#   Relative paths resolve against the install directory. The environment is
#   inherited too, so GOMEMLIMIT=3GiB ./update.sh ... applies to the new enode.
#
#   When an enode is already running from this directory (its pid file names a
#   live enode process), it is not restarted: it is sent SIGUSR2 and hands every
#   connection over to the new binary, so no client is disconnected. The new
#   process keeps the running one's arguments; the ones given here are not used.
#   See docs/server-handoff.md. Not on Windows, which cannot pass sockets between
#   processes: stop enode there first.
#
# Environment:
#   ENODE_REPO          GitHub owner/repo to update from (default ModderMule/eNode-go)
#   ENODE_VERSION       install this tag (e.g. v0.3.4) instead of the latest release
#   UPDATE_INSECURE     non-empty disables TLS verification (see below)
#   ENODE_PIDFILE       the running enode's pid file, if the config moved it from
#                       pidFile's default (data/enode.pid, relative to this directory)
#   ENODE_NO_HANDOFF    non-empty skips the handover and starts enode as before
#   ENODE_HANDOFF_WAIT  seconds to wait for a handover to finish (default 900); a
#                       refused or failed one is reported as soon as enode says so
#
# An existing enode.config.yaml is never overwritten: it carries the operator's
# settings, and enode has no overlay file. The release's copy is written next to
# it as enode.config.yaml.new so new keys can be merged by hand.
#
# Everything lives in main() and the file ends with `main "$@"; exit`. Bash
# reads a script incrementally, and this one replaces itself with the bundle's
# copy; parsing the whole function up front keeps that from executing a mix of
# old and new bytes.

usage() {
  sed -n 's/^# \{0,1\}//; /^Usage:/,/^Environment:/p' "$0" | sed '$d'
}

main() {
  # Only -h/--help as the first argument is the script's own; everything else
  # belongs to enode, including the value of a flag such as -config.
  case "${1:-}" in
    -h|--help) usage; exit 0 ;;
  esac
  local START_ARGS=("$@")

  # --- install dir: wherever this script sits -----------------------------
  local DIR
  DIR="$(cd "$(dirname "$0")" && pwd)"
  cd "$DIR"

  # The repo itself also contains scripts/update.sh; running it there would
  # spray a release bundle over the source tree.
  if [[ -e "$DIR/.git" || ( "$(basename "$DIR")" == "scripts" && -e "$DIR/../go.mod" ) ]]; then
    echo "error: $DIR is a git checkout; copy update.sh into the install directory and run it there" >&2
    exit 1
  fi

  local REPO="${ENODE_REPO:-ModderMule/eNode-go}"

  # --- platform -------------------------------------------------------------
  # Only the targets .github/workflows/{linux,macos,windows}.yml build.
  local OS ARCH PLAT EXT EXE=""
  OS="$(uname -s)"
  ARCH="$(uname -m)"
  case "$OS/$ARCH" in
    Linux/x86_64|Linux/amd64)                  PLAT="linux-amd64"; EXT="tar.gz" ;;
    Darwin/arm64|Darwin/aarch64)               PLAT="macos-arm64"; EXT="tar.gz" ;;
    MINGW*/x86_64|MSYS*/x86_64|CYGWIN*/x86_64) PLAT="win64";       EXT="zip"; EXE=".exe" ;;
    *)
      echo "error: unsupported platform ${OS}/${ARCH}; supported: linux/amd64, macos/arm64, windows/amd64 (Git Bash)" >&2
      exit 1
      ;;
  esac

  # --- required tools -------------------------------------------------------
  need curl
  if [[ "$EXT" == "zip" ]]; then need unzip; else need tar; fi
  local SHA_CMD
  if command -v sha256sum >/dev/null 2>&1; then
    SHA_CMD=(sha256sum)
  elif command -v shasum >/dev/null 2>&1; then
    SHA_CMD=(shasum -a 256)
  else
    echo "error: neither sha256sum nor shasum found; cannot verify the download" >&2
    exit 1
  fi

  # TLS verification stays on unless the operator opts out for a host with a
  # self-signed certificate. Turning it off by default would silently accept any
  # tarball a network attacker cared to serve, and this one is executed.
  CURL_OPTS=(-fsSL)
  if [[ -n "${UPDATE_INSECURE:-}" ]]; then
    echo "WARNING: UPDATE_INSECURE is set — the download is not authenticated."
    CURL_OPTS+=(--insecure)
  fi

  # --- target version -------------------------------------------------------
  # releases/latest skips drafts and pre-releases, so a tag only becomes visible
  # here once its draft has been published.
  local TAG="${ENODE_VERSION:-}"
  if [[ -z "$TAG" ]]; then
    TAG="$(curl "${CURL_OPTS[@]}" "https://api.github.com/repos/${REPO}/releases/latest" \
      | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)" || true
    if [[ -z "$TAG" ]]; then
      echo "error: could not determine the latest release of ${REPO} (no published release, or GitHub API rate limit)" >&2
      echo "       set ENODE_VERSION=vX.Y.Z to pick a tag explicitly" >&2
      exit 1
    fi
  fi
  [[ "$TAG" == v* ]] || TAG="v${TAG}"

  local NAME="enode-${TAG}-${PLAT}"
  local ASSET="${NAME}.${EXT}"
  local BASE="https://github.com/${REPO}/releases/download/${TAG}"

  echo "Platform:  ${PLAT}"
  echo "Release:   ${REPO} ${TAG}"
  echo "Install:   ${DIR}"
  echo

  # --- download + verify into a staging dir ---------------------------------
  STAGE="$(mktemp -d)"
  trap 'rm -rf "$STAGE"' EXIT

  echo "Downloading ${ASSET} ..."
  curl "${CURL_OPTS[@]}" -o "$STAGE/$ASSET" "$BASE/$ASSET"
  curl "${CURL_OPTS[@]}" -o "$STAGE/$ASSET.sha256" "$BASE/$ASSET.sha256"

  # The .sha256 records a bare filename, so -c must run next to the archive.
  if ! (cd "$STAGE" && "${SHA_CMD[@]}" -c "$ASSET.sha256" >/dev/null); then
    echo "error: checksum mismatch for ${ASSET}; nothing was installed" >&2
    exit 1
  fi
  echo "Checksum OK."

  if [[ "$EXT" == "zip" ]]; then
    unzip -q "$STAGE/$ASSET" -d "$STAGE"
  else
    tar -xzf "$STAGE/$ASSET" -C "$STAGE"
  fi
  local SRC="$STAGE/$NAME"
  if [[ ! -x "$SRC/enode${EXE}" && ! -f "$SRC/enode${EXE}" ]]; then
    echo "error: ${ASSET} does not contain ${NAME}/enode${EXE}" >&2
    exit 1
  fi

  # --- keep the operator's config ------------------------------------------
  if [[ -f "$DIR/enode.config.yaml" && -f "$SRC/enode.config.yaml" ]]; then
    mv "$SRC/enode.config.yaml" "$SRC/enode.config.yaml.new"
    echo "Kept existing enode.config.yaml; the release copy is enode.config.yaml.new (diff it for new keys)."
  fi

  # --- install --------------------------------------------------------------
  # Each file is removed before it is copied. On Linux, writing into a running
  # binary fails with "Text file busy", and on macOS rewriting a signed binary in
  # place can get it killed; unlinking first gives the new file a fresh inode
  # while a running enode keeps the old one. On Windows a running enode.exe is
  # locked and cannot be removed at all.
  local f rel
  while IFS= read -r f; do
    rel="${f#"$SRC"/}"
    mkdir -p "$DIR/$(dirname "$rel")"
    if ! { rm -f "$DIR/$rel" && cp -p "$f" "$DIR/$rel"; }; then
      echo "error: could not replace ${rel}; stop enode (and natsim) first and re-run" >&2
      exit 1
    fi
  done < <(find "$SRC" -type f)
  chmod +x "$DIR/enode${EXE}" "$DIR"/natsim*"${EXE}" "$DIR/update.sh" 2>/dev/null || true

  echo "Installed ${TAG}."
  echo

  # --- hand over --------------------------------------------------------------
  # A running enode is told to start the new binary and pass it every socket and
  # session; it exits once the new one serves. Only an enode that writes a pid file
  # can do that, so a missing file means an older version, which SIGUSR2 would
  # simply kill — it is left alone, and the start below fails to bind until it is
  # stopped. The process name is checked so a stale file whose pid has been reused
  # never signals an unrelated process.
  local PIDFILE="${ENODE_PIDFILE:-$DIR/data/enode.pid}"
  if [[ -z "$EXE" && -z "${ENODE_NO_HANDOFF:-}" && -f "$PIDFILE" ]]; then
    local OLD
    OLD="$(tr -cd '0-9' < "$PIDFILE")"
    if [[ -n "$OLD" ]] && kill -0 "$OLD" 2>/dev/null && ps -p "$OLD" -o comm= 2>/dev/null | grep -q enode; then
      handover "$OLD" "$PIDFILE" "${ENODE_HANDOFF_WAIT:-900}"
      exit
    fi
  fi

  # --- start ----------------------------------------------------------------
  echo "Starting ./enode${EXE} ${START_ARGS[*]:-}"
  exec "./enode${EXE}" ${START_ARGS[@]+"${START_ARGS[@]}"}
}

# handover signals the running enode $1 and waits up to $3 seconds for it to exit
# and for the pid file $2 to name its successor.
handover() {
  local old="$1" pidfile="$2" wait="$3" new="" i
  # enode writes why a handover did not happen to this file (handoff.memory: off,
  # a successor that failed to start, ...), and keeps serving.
  local status="${pidfile}.handoff"
  echo "enode is running as pid ${old}: handing its connections over to the new binary ..."
  rm -f "$status"
  kill -USR2 "$old"
  for ((i = 0; i < wait; i++)); do
    if [[ -s "$status" ]]; then
      echo "error: no handover: $(cat "$status")" >&2
      echo "enode is still running the previous version as pid ${old}; restart it to run the new one." >&2
      return 1
    fi
    if ! kill -0 "$old" 2>/dev/null; then
      new="$(tr -cd '0-9' < "$pidfile" 2>/dev/null || true)"
      if [[ -n "$new" && "$new" != "$old" ]] && kill -0 "$new" 2>/dev/null; then
        echo "Handed over: enode is running as pid ${new}."
        return 0
      fi
    fi
    sleep 1
  done
  if kill -0 "$old" 2>/dev/null; then
    echo "error: pid ${old} is still serving after ${wait}s; the handover failed or is still running — see the log" >&2
  else
    echo "error: pid ${old} exited but no new enode is running — see the log, then start enode" >&2
  fi
  return 1
}

need() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "error: required tool '$1' not found" >&2
    exit 1
  fi
}

main "$@"; exit
