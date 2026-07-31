#!/usr/bin/env bash
set -euo pipefail

# Confirms the checked-in rockspec's filename and its internal `version`
# field agree, and that the version hasn't already been released as a git
# tag, so a PR can't ship a rockspec that installs under one version while
# claiming another, or silently reuse a version that's already out.
#
# Usage: ./check_rockspec_version.sh [path-to-rockspec]

ROCKSPEC="${1:-$(ls ./lua_resty_netacea-*.rockspec 2>/dev/null | head -n1)}"

if [ -z "$ROCKSPEC" ] || [ ! -f "$ROCKSPEC" ]; then
  echo "No rockspec found (expected ./lua_resty_netacea-*.rockspec)." >&2
  exit 1
fi

BASENAME="$(basename "$ROCKSPEC")"
if [[ ! "$BASENAME" =~ ^lua_resty_netacea-([0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9]+)?)-([0-9]+)\.rockspec$ ]]; then
  echo "Rockspec filename '$BASENAME' doesn't match the expected lua_resty_netacea-<version>-<revision>.rockspec pattern." >&2
  exit 1
fi
RELEASE_VERSION="${BASH_REMATCH[1]}"
REVISION="${BASH_REMATCH[3]}"
FILE_VERSION="${RELEASE_VERSION}-${REVISION}"

FIELD_VERSION="$(grep -E '^version[[:space:]]*=' "$ROCKSPEC" | head -n1 | sed -E 's/^version[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/')"

if [ -z "$FIELD_VERSION" ]; then
  echo "Could not find a version = \"...\" field in $ROCKSPEC." >&2
  exit 1
fi

if [ "$FILE_VERSION" != "$FIELD_VERSION" ]; then
  echo "Rockspec filename version ($FILE_VERSION) doesn't match its version field ($FIELD_VERSION)." >&2
  exit 1
fi

TAG="v${RELEASE_VERSION}"
if git rev-parse -q --verify "refs/tags/$TAG" >/dev/null; then
  echo "Tag $TAG already exists; bump the version in $ROCKSPEC before merging." >&2
  exit 1
fi

echo "OK: $BASENAME matches version field ($FIELD_VERSION) and tag $TAG is unused."
