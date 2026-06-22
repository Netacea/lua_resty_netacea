# Contributing to `lua_resty_netacea`

## Before you start

This repository is for developing the Lua package that is published
through Luarocks. The Netacea team handles publishing.

Use the existing Docker-based workflow unless you have a specific reason not to:

1. Create `./.env` from `./.env.example`.
2. Fill in the Netacea environment variables required for the mode you want to test.
3. Update `./src/conf/nginx.conf` if you need a local server configuration.

## Local development

Start the development container with:

```sh
docker compose up --build resty
```

The module will be available on `http://localhost:8080`.

## Testing

Run unit tests in the dev container with:

```sh
./run_lua_tests.sh
```

To include coverage output:

```sh
export LUACOV_REPORT=1 && ./run_lua_tests.sh
```

You can also run tests through Docker Compose:

```sh
docker compose run --rm --build test
```

For coverage through Docker Compose:

```sh
docker compose run -e LUACOV_REPORT=1 --build test
```

## Linting

Run the linter with:

```sh
docker compose run --rm --build lint
```

## Code style and changes

- Keep changes focused and consistent with the existing Lua style in `src/` and `test/`.
- Add or update tests when behavior changes.
- Prefer small, reviewable changes over broad refactors unless a refactor is part of the task.

## Updating the version number

When releasing a new version, update all version references together:

1. Update [`src/lua_resty_netacea.lua`](/home/user/github/lua_resty_netacea/src/lua_resty_netacea.lua) and change `_N._VERSION` to the new library version, for example `1.2.2`.
2. Rename the rockspec file to match the new release, for example `lua_resty_netacea-1.2.2-0.rockspec`.
3. Update the `version = "..."` field inside the rockspec to the same value.
4. Update any build files that reference the rockspec filename:
   - [`Dockerfile`](/home/user/github/lua_resty_netacea/Dockerfile)
   - [`Dockerfile.nginx_lua`](/home/user/github/lua_resty_netacea/Dockerfile.nginx_lua)
5. Update any other hardcoded version references you introduce in future changes.

The package version and the rockspec version should stay in sync, with the rockspec using the `-0` release suffix.

## Security issues

Report security issues by email to [security@netacea.com](mailto:security@netacea.com).
Include a description of the issue, the steps to reproduce it, affected versions, and any known mitigations.
