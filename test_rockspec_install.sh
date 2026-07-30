#!/usr/bin/env bash
set -euo pipefail

# Installs this package from its rockspec into a throwaway tree and confirms
# every module it require()s at load time actually shipped: luarocks only
# packages what's listed under build.modules, so anything left off that list
# fails at runtime, not at install time, which "luarocks make" alone won't catch.
#
# Usage: ./test_rockspec_install.sh [path-to-rockspec]

ROCKSPEC="${1:-$(ls ./lua_resty_netacea-*.rockspec | head -n1)}"
LUAROCKS="${LUAROCKS_BIN:-luarocks}"
NGINX="${NGINX_BIN:-/usr/local/openresty/nginx/sbin/nginx}"
TEST_PORT="${TEST_PORT:-18099}"

if [ ! -f "$ROCKSPEC" ]; then
  echo "Rockspec not found: $ROCKSPEC" >&2
  exit 1
fi

WORKDIR="$(mktemp -d)"
TREE="$WORKDIR/tree"
PREFIX="$WORKDIR/nginx"
NGINX_PID=""
cleanup() {
  [ -n "$NGINX_PID" ] && kill "$NGINX_PID" 2>/dev/null || true
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

echo "==> luarocks lint $ROCKSPEC"
"$LUAROCKS" lint "$ROCKSPEC"

echo "==> installing into throwaway tree: $TREE"
"$LUAROCKS" --tree="$TREE" make "$ROCKSPEC"

echo "==> smoke-testing require(\"lua_resty_netacea\") inside an OpenResty worker"
mkdir -p "$PREFIX/logs" "$PREFIX/conf"
cat > "$PREFIX/conf/nginx.conf" <<EOF
worker_processes 1;
daemon off;
error_log $PREFIX/logs/error.log info;
pid $PREFIX/logs/nginx.pid;
events { worker_connections 16; }
http {
  lua_package_path "$TREE/share/lua/5.1/?.lua;;";
  lua_package_cpath "$TREE/lib/lua/5.1/?.so;;";
  server {
    listen $TEST_PORT;
    location /test {
      content_by_lua_block {
        local ok, mod = pcall(require, "lua_resty_netacea")
        if ok then
          ngx.say("REQUIRE_OK version=" .. tostring(mod._VERSION))
        else
          ngx.status = 500
          ngx.say("REQUIRE_FAIL " .. tostring(mod))
        end
      }
    }
  }
}
EOF

"$NGINX" -p "$PREFIX" -c conf/nginx.conf &
NGINX_PID=$!

RESPONSE=""
for _ in $(seq 1 20); do
  if RESPONSE="$(curl -sf "http://127.0.0.1:$TEST_PORT/test" 2>/dev/null)"; then
    break
  fi
  sleep 0.5
done
echo "$RESPONSE"

case "$RESPONSE" in
  REQUIRE_OK*) echo "PASS: rockspec installs a working module" ;;
  *)
    echo "FAIL: $RESPONSE" >&2
    exit 1
    ;;
esac
