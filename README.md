# lua_resty_netacea

An Openresty module for easy integration of Netacea services. This repo is for developing the package. The package can be accessed by the Luarocks package management platform. See the Netacea documentation for making use of the module.

## Published package

The Netacea package is available on the Luarocks package manager. Publishing is handled by the Netacea team.

## Docker images

The Dockerfile contains a multi-stage build, including:

| Stage name | Based on | Description |
| -- | -- | -- |
| base  |  openresty/openresty:noble | Base image of Openresty with updated packages around openSSL |
| build | base | Working Openresty instance with Netacea plugin installed using luarocks and rockspec file |
| test | build | Lua packages installed for testing and linting. Command overridden to run unit tests |
| lint | test | Command overridden to run luacheck linter and output results |

The docker compose file is used to mount local files to the right place in the image to support development.

### Environment variables

The Docker Compose services that run NGINX load Netacea configuration from a local `.env` file.
Create it from the example file, then fill in the values provided by the Netacea Solutions Engineering team:

```sh
cp .env.example .env
```

The `.env` file is ignored by git because it can contain sensitive values such as API keys, cookie encryption keys, and Kinesis credentials.
Keep `.env.example` updated when adding or removing configuration variables.

### Run development version

1. Create `./.env` from `./.env.example` and set the Netacea environment variables.
2. Update `./src/conf/nginx.conf` to include server configuration. See "Configuration" below.
3. `docker compose up --build resty`
4. Access [](http://localhost:8080)

### Run tests

#### Unit tests

##### In dev container

Without coverage report: `./run_lua_tests.sh`
With coverage report (sent to stdout) `export LUACOV_REPORT=1 && ./run_lua_tests.sh`

##### Docker compose

Without coverage report: `docker compose run --rm --build test`
With coverage report (sent to stdout) `docker compose run -e LUACOV_REPORT=1 --build test [> output.html]`

#### Linter

`docker compose run --rm --build lint`

## Configuration

### .env - ingest only

Use ingest-only mode when you want to send request data to the ingest pipeline without calling the Mitigation Endpoint.

Ingest is enabled by default. Set `NETACEA_PROTECTION_MODE` to `INGEST`.

Kinesis properties must be provided for ingest to remain enabled.

When `realIpHeaderIndex` is set, `realIpHeader` is parsed as a comma-separated list and the indexed value is used. Indexing starts at `0`; negative indexes count from the end, so `-1` selects the last value.
This is useful for, though not limited to, parsing `X-Forwarded-For` values.

```dotenv
NETACEA_PROTECTION_MODE=INGEST
NETACEA_API_KEY=your-api-key
NETACEA_COOKIE_ENCRYPTION_KEY=your-cookie-encryption-key
NETACEA_COOKIE_NAME=your-session-cookie-name
NETACEA_CAPTCHA_COOKIE_NAME=your-captcha-cookie-name
NETACEA_REAL_IP_HEADER=X-Forwarded-For
NETACEA_REAL_IP_HEADER_INDEX=0
NETACEA_KINESIS_ACCESS_KEY=your-aws-access-key
NETACEA_KINESIS_SECRET_KEY=your-aws-secret-key
NETACEA_KINESIS_STREAM_NAME=your-kinesis-stream
```

### .env - mitigate

Use MITIGATE as the NETACEA_PROTECTION_MODE when you want the integration to
call the Protector API and enforce mitigation responses.

```dotenv
NETACEA_PROTECTION_MODE=MITIGATE
NETACEA_API_KEY=your-api-key
NETACEA_COOKIE_ENCRYPTION_KEY=your-cookie-encryption-key
NETACEA_COOKIE_NAME=your-session-cookie-name
NETACEA_CAPTCHA_COOKIE_NAME=your-captcha-cookie-name
NETACEA_REAL_IP_HEADER=X-Forwarded-For
NETACEA_REAL_IP_HEADER_INDEX=0
NETACEA_KINESIS_ACCESS_KEY=your-aws-access-key
NETACEA_KINESIS_SECRET_KEY=your-aws-secret-key
NETACEA_KINESIS_STREAM_NAME=your-kinesis-stream
NETACEA_PROTECTOR_API_URL=https://your-protector-api-url
```

### .env - inject

Use INJECT as the NETACEA_PROTECTION_MODE when you want the integration to
call the Protector API but defer mitigation to downstream services.

```dotenv
NETACEA_PROTECTION_MODE=INJECT
NETACEA_API_KEY=your-api-key
NETACEA_COOKIE_ENCRYPTION_KEY=your-cookie-encryption-key
NETACEA_COOKIE_NAME=your-session-cookie-name
NETACEA_CAPTCHA_COOKIE_NAME=your-captcha-cookie-name
NETACEA_REAL_IP_HEADER=X-Forwarded-For
NETACEA_REAL_IP_HEADER_INDEX=0
NETACEA_KINESIS_ACCESS_KEY=your-aws-access-key
NETACEA_KINESIS_SECRET_KEY=your-aws-secret-key
NETACEA_KINESIS_STREAM_NAME=your-kinesis-stream
NETACEA_PROTECTOR_API_URL=https://your-protector-api-url
```

### Environment variable default values reference

| Environment variable                | Default                  |
| ----------------------------------- | ------------------------ |
| `NETACEA_PROTECTION_MODE`           | `INGEST`                 |
| `NETACEA_INGEST_ENABLED`            | `true`                   |
| `NETACEA_PROTECTOR_API_URL`         | `""`                     |
| `NETACEA_API_KEY`                   | none                     |
| `NETACEA_COOKIE_ENCRYPTION_KEY`     | none                     |
| `NETACEA_SECRET_KEY`                | none                     |
| `NETACEA_COOKIE_NAME`               | `_mitata`                |
| `NETACEA_CAPTCHA_COOKIE_NAME`       | `_mitatacaptcha`         |
| `NETACEA_COOKIE_ATTRIBUTES`         | `Max-Age=86400; Path=/;` |
| `NETACEA_CAPTCHA_COOKIE_ATTRIBUTES` | `Max-Age=86400; Path=/;` |
| `NETACEA_REAL_IP_HEADER`            | `""`                     |
| `NETACEA_REAL_IP_HEADER_INDEX`      | unset                    |
| `NETACEA_KINESIS_ACCESS_KEY`        | `""`                     |
| `NETACEA_KINESIS_SECRET_KEY`        | `""`                     |
| `NETACEA_KINESIS_STREAM_NAME`       | `""`                     |
| `NETACEA_KINESIS_REGION`            | `eu-west-1`              |
| `NETACEA_KINESIS_BATCH_SIZE`        | `25`                     |
| `NETACEA_KINESIS_BATCH_TIMEOUT`     | `1.0`                    |
