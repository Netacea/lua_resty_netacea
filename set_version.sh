#! /bin/bash

## Updates the version number in the relevant parts of the integration

new_version=$1

if ! [[ "$new_version" =~ ^[0-9]+\.[0-9]+\-[0-9]+$ ]]; then
    echo "'$new_version' doesn't match the version pattern {major}.{minor}-{patch}"
    exit 1
fi

current_version=`ls lua_resty_netacea-*.rockspec | grep -oP [0-9]+\.[0-9]+\-[0-9]+`

mv lua_resty_netacea-$current_version.rockspec lua_resty_netacea-$new_version.rockspec 

sed -i "s/version = \"[^\"]*\"/version = \"${new_version}\"/g" lua_resty_netacea-$new_version.rockspec
sed -i "s/_N._VERSION = '[^\']*'/_N._VERSION = '${new_version}'/g" ./src/lua_resty_netacea.lua
