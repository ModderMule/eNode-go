#!/usr/bin/env bash
set -euo pipefail

# Interactive release helper for eNode-go.
#
# Bumps ENodeVersionStr in ed2k/constants.go -- the single source of truth for
# the version -- then creates a release commit + annotated git tag and pushes
# both. The GitHub build workflows (.github/workflows/{linux,windows,macos}.yml)
# read that same constant to name their artifacts, so tag, artifact and the
# version the binary reports all stay in lockstep.
#
# ENodeVersionInt (the ed2k wire-protocol version) is deliberately NOT bumped
# here; it changes only when the protocol changes.
#
# Usage: scripts/publish-release.sh

# --- locate repo root -------------------------------------------------------
if ! ROOT="$(git rev-parse --show-toplevel 2>/dev/null)"; then
  echo "error: not inside a git repository" >&2
  exit 1
fi
cd "$ROOT"

# --- guard: clean working tree ---------------------------------------------
if [[ -n "$(git status --porcelain)" ]]; then
  echo "error: working tree has uncommitted changes; commit or stash them first" >&2
  git status --short >&2
  exit 1
fi

BRANCH="$(git rev-parse --abbrev-ref HEAD)"
REMOTE="origin"

# --- current version + suggested next patch bump ---------------------------
CONST_FILE="ed2k/constants.go"
CURRENT="$(sed -n 's/.*ENodeVersionStr[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$CONST_FILE")"
CURRENT="${CURRENT:-v0.0.0}"

# strip leading 'v', split into major.minor.patch, suggest patch+1
suggest="v0.0.1"
if [[ "$CURRENT" =~ ^v?([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
  suggest="v${BASH_REMATCH[1]}.${BASH_REMATCH[2]}.$(( BASH_REMATCH[3] + 1 ))"
fi

echo "Current version: ${CURRENT}"
echo "Branch:          ${BRANCH} (remote: ${REMOTE})"
echo

# --- prompt for new version -------------------------------------------------
read -r -p "New version [${suggest}]: " NEW
NEW="${NEW:-$suggest}"
# normalize a leading 'v'
[[ "$NEW" == v* ]] || NEW="v${NEW}"

if [[ ! "$NEW" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "error: '${NEW}' is not a valid vMAJOR.MINOR.PATCH version" >&2
  exit 1
fi

if git rev-parse -q --verify "refs/tags/${NEW}" >/dev/null; then
  echo "error: tag ${NEW} already exists" >&2
  exit 1
fi

# --- record the version in the source of truth ------------------------------
sed -i.bak "s#\(ENodeVersionStr[[:space:]]*=[[:space:]]*\)\"[^\"]*\"#\1\"${NEW}\"#" "$CONST_FILE"
rm -f "${CONST_FILE}.bak"
GOT="$(sed -n 's/.*ENodeVersionStr[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$CONST_FILE")"
if [[ "$GOT" != "$NEW" ]]; then
  echo "error: failed to bump ENodeVersionStr in ${CONST_FILE} (got '${GOT}')" >&2
  git checkout -- "$CONST_FILE"
  exit 1
fi
git add "$CONST_FILE"

# --- confirm ----------------------------------------------------------------
echo
echo "About to:"
echo "  commit : release: ${NEW}   (ENodeVersionStr -> ${NEW})"
echo "  tag    : ${NEW}  (annotated)"
echo "  push   : ${REMOTE} ${BRANCH}  and  ${REMOTE} ${NEW}"
echo
read -r -p "Proceed? [y/N]: " CONFIRM
if [[ "${CONFIRM,,}" != "y" ]]; then
  echo "aborted; reverting ${CONST_FILE}"
  git restore --staged "$CONST_FILE"
  git checkout -- "$CONST_FILE"
  exit 1
fi

# --- commit / tag / push ----------------------------------------------------
git commit -m "release: ${NEW}"
git tag -a "${NEW}" -m "Release ${NEW}"
git push "${REMOTE}" "${BRANCH}"
git push "${REMOTE}" "${NEW}"

echo
echo "Released ${NEW}."
echo "Next: GitHub -> Actions -> run the Linux/Windows/macOS workflows to build artifacts for this tag."
