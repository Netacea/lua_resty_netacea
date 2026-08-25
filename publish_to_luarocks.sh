#!/usr/bin/env bash
set -euo pipefail

# Publishes a tagged release of this rock to luarocks.org.
#
# Usage:
#   LUAROCKS_API_KEY=xxx ./publish_to_luarocks.sh v1.6.0
#
# The checked-in rockspec's `source` block tracks the master branch, which is
# fine for local `luarocks make` but wrong for a release: `luarocks upload`
# re-fetches source from that block rather than the local working tree, so
# uploading it as-is would ship whatever master happens to be at upload time,
# not the tagged commit. This script uploads a temporary copy of the rockspec
# with `source.tag` pinned to the release tag instead, so the published rock
# is reproducible from that tag.

TAG="${1:?usage: $0 <git-tag>}"
LUAROCKS="${LUAROCKS_BIN:-luarocks}"
: "${LUAROCKS_API_KEY:?LUAROCKS_API_KEY must be set}"

if [[ ! "$TAG" =~ ^v?[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "Tag '$TAG' doesn't look like a release tag (expected e.g. v1.6.0)." >&2
  exit 1
fi
VERSION="${TAG#v}"
ROCKSPEC="lua_resty_netacea-${VERSION}-0.rockspec"

if [ ! -f "$ROCKSPEC" ]; then
  echo "No rockspec found for tag $TAG (expected $ROCKSPEC)." >&2
  echo "The rockspec version must be bumped in lockstep with the release tag; see CONTRIBUTING.md." >&2
  exit 1
fi

if ! git rev-parse -q --verify "refs/tags/$TAG" >/dev/null; then
  echo "Git tag $TAG does not exist locally." >&2
  exit 1
fi

if [ "$(git rev-parse HEAD)" != "$(git rev-parse "refs/tags/$TAG^{commit}")" ]; then
  echo "Working tree HEAD does not match tag $TAG; checkout the tag before publishing." >&2
  exit 1
fi

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT
PINNED_ROCKSPEC="$WORKDIR/$ROCKSPEC"

sed -E "s/branch = \"master\"/tag = \"$TAG\"/" "$ROCKSPEC" > "$PINNED_ROCKSPEC"
if ! grep -q "tag = \"$TAG\"" "$PINNED_ROCKSPEC"; then
  echo "Failed to pin source.tag in $ROCKSPEC; check its source block." >&2
  exit 1
fi

echo "==> linting pinned rockspec"
"$LUAROCKS" lint "$PINNED_ROCKSPEC"

echo "==> uploading $ROCKSPEC (source pinned to $TAG) to luarocks.org"
"$LUAROCKS" upload "$PINNED_ROCKSPEC" --temp-key="$LUAROCKS_API_KEY"

echo "Published lua_resty_netacea $VERSION from tag $TAG."
