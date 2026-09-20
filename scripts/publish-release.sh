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
# The tag push is also what produces the release: each of those three workflows
# attaches its bundle and a matching .sha256 to a DRAFT GitHub Release for the
# tag. The first run to finish creates the draft, the other two append to it --
# there is deliberately no shared `concurrency` group, because GitHub holds only
# ONE pending run per group and a third arrival would cancel the queued second
# rather than queue behind it. Nothing in this script talks to the GitHub API;
# write the notes on the draft and publish it by hand once all three are green.
#
# There is no combined SHA256SUMS.txt for the same reason: three independent
# workflows cannot append to one file without racing, so each ships its own.
#
# GossipVersionStr -- the ST_VERSION (0x91) value we advertise to peer servers
# and to clients -- IS bumped, but by derivation: it is a const expression built
# from ENodeVersionStr, so the single sed below carries it. Its leading "17.14"
# is a Lugdunum protocol-compatibility claim and must never move with a release;
# see the guard further down.
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

# GossipVersionStr -- the ST_VERSION we advertise to peer servers and to clients --
# is derived from ENodeVersionStr, so the bump above carries it. Checked rather than
# assumed: if it is ever unpicked into a literal, a release would keep telling the
# ed2k network the previous version, and nothing else in the build would notice.
if ! grep -qE 'GossipVersionStr[[:space:]]*=.*ENodeVersionStr' "$CONST_FILE"; then
  echo "error: GossipVersionStr in ${CONST_FILE} no longer derives from ENodeVersionStr;" >&2
  echo "       the version advertised over ed2k would not have been bumped" >&2
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
echo "The tag push starts .github/workflows/{linux,macos,windows}.yml; each"
echo "attaches its bundle and .sha256 to a DRAFT release for ${NEW}."
echo
echo "Finish with: write the notes on the draft, then publish it."

# --- where to watch ---------------------------------------------------------
# The sed strips any credentials embedded in the remote URL before printing it.
# origin may carry a token, and it must not be echoed to the terminal.
REPO_URL="$(git remote get-url "${REMOTE}" \
  | sed -E 's#^https://[^@/]*@#https://#; s#^git@github\.com:#https://github.com/#; s#\.git$##')"

echo
echo "Actions:  ${REPO_URL}/actions"
echo "Releases: ${REPO_URL}/releases"

# --- optional: dispatch the builds manually ---------------------------------
# Not needed while .github/workflows/*.yml carry their `push: tags: ['v*']`
# trigger -- the tag push above already starts all three, and dispatching here
# would build every release twice. Uncomment only if that trigger is removed
# again, or to force a rebuild of this tag.
#
# Requires a gh account with write access to the repo; dispatch is an
# actions:write operation, so a read-only login fails with 403. `|| true`
# keeps a failed dispatch from taking down an otherwise-successful release,
# since `set -e` is in effect and the tag is already pushed by this point.
#
# if command -v gh >/dev/null 2>&1; then
#   read -r -p "Trigger the build workflows for ${NEW} now? [y/N]: " BUILD
#   if [[ "${BUILD,,}" == "y" ]]; then
#     for wf in linux.yml windows.yml macos.yml; do
#       gh workflow run "$wf" --ref "${NEW}" || true
#     done
#     echo "Dispatched; watch with: gh run list --limit 3"
#   fi
# fi
