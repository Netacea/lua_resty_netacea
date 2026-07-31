#!/usr/bin/env bash
set -euo pipefail

# Bumps the library to a new version in every place check_rockspec_version.sh
# checks: renames the rockspec, updates its `version` field, and updates
# _N._VERSION in src/lua_resty_netacea.lua. Always uses the "-0" release
# suffix (see CONTRIBUTING.md).
#
# Usage: ./bump_version.sh <new-version>
# Example: ./bump_version.sh 1.6.3

NEW_VERSION="${1:?usage: $0 <new-version, e.g. 1.6.3>}"

if [[ ! "$NEW_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "Version '$NEW_VERSION' doesn't look like <major>.<minor>.<patch>, e.g. 1.6.3." >&2
  exit 1
fi

SOURCE_FILE="$(dirname "$0")/src/lua_resty_netacea.lua"
OLD_ROCKSPEC="$(ls ./lua_resty_netacea-*.rockspec 2>/dev/null | head -n1)"

if [ -z "$OLD_ROCKSPEC" ] || [ ! -f "$OLD_ROCKSPEC" ]; then
  echo "No existing rockspec found (expected ./lua_resty_netacea-*.rockspec)." >&2
  exit 1
fi

NEW_ROCKSPEC="./lua_resty_netacea-${NEW_VERSION}-0.rockspec"

if [ "$OLD_ROCKSPEC" = "$NEW_ROCKSPEC" ]; then
  echo "$OLD_ROCKSPEC is already at version $NEW_VERSION." >&2
  exit 1
fi

if [ -e "$NEW_ROCKSPEC" ]; then
  echo "$NEW_ROCKSPEC already exists." >&2
  exit 1
fi

if git -C "$(dirname "$0")" rev-parse --git-dir >/dev/null 2>&1; then
  git mv "$OLD_ROCKSPEC" "$NEW_ROCKSPEC"
else
  mv "$OLD_ROCKSPEC" "$NEW_ROCKSPEC"
fi

sed -i -E "s/^version[[:space:]]*=[[:space:]]*\"[^\"]+\"/version = \"${NEW_VERSION}-0\"/" "$NEW_ROCKSPEC"
sed -i -E "s/^_N\._VERSION[[:space:]]*=[[:space:]]*'[^']+'/_N._VERSION = '${NEW_VERSION}'/" "$SOURCE_FILE"

echo "Bumped to $NEW_VERSION:"
echo "  $NEW_ROCKSPEC"
echo "  $SOURCE_FILE"

"$(dirname "$0")/check_rockspec_version.sh" "$NEW_ROCKSPEC"
