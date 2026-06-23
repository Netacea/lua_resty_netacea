# lua_resty_netacea

An Openresty module for easy integration of Netacea services. This repo is for
developing the package. The package can be accessed by the Luarocks package
management platform. See the Netacea documentation for making use of the module.

## Published package

The Netacea package is available on the Luarocks package manager.
Publishing is handled by the Netacea team.

## Contributing to this Repository

If you wish to make a contribution to this repository, please see
[CONTRIBUTING.md](/home/user/github/lua_resty_netacea/CONTRIBUTING.md).

## Docker images

This repository includes Dockerfiles and Docker Compose services for running the
existing code without making any changes.

### Prerequisites

- Docker Engine or Docker Desktop
- Docker Compose
- A local `.env` file if you want to supply Netacea runtime values

### Build the image

To build the OpenResty image used by the `resty` service:

```sh
docker compose build resty
```

This uses [`Dockerfile`](/home/user/github/lua_resty_netacea/Dockerfile) and
builds the package from the checked-in rockspec and source files.

### Run the module locally

The `resty` service starts OpenResty with the module loaded and exposes it on
`http://localhost:8080`:

```sh
docker compose up --build resty
```

Before starting it, create a `.env` file from `.env.example` and set the
runtime values required by your selected protection mode.

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
| `NETACEA_API_KEY`                   | none                     |
| `NETACEA_CAPTCHA_COOKIE_ATTRIBUTES` | `Max-Age=86400; Path=/;` |
| `NETACEA_CAPTCHA_COOKIE_NAME`       | `_mitatacaptcha`         |
| `NETACEA_ENABLE_CAPTCHA_CONTENT_NEGOTIATION` | `false`          |
| `NETACEA_CAPTCHA_PATH`              | unset                    |
| `NETACEA_CHECKPOINT_SIGNAL_PATH`    | unset                    |
| `NETACEA_COOKIE_ATTRIBUTES`         | `Max-Age=86400; Path=/;` |
| `NETACEA_COOKIE_ENCRYPTION_KEY`     | none                     |
| `NETACEA_COOKIE_NAME`               | `_mitata`                |
| `NETACEA_INGEST_ENABLED`            | `true`                   |
| `NETACEA_KINESIS_ACCESS_KEY`        | `""`                     |
| `NETACEA_KINESIS_BATCH_SIZE`        | `25`                     |
| `NETACEA_KINESIS_BATCH_TIMEOUT`     | `1.0`                    |
| `NETACEA_KINESIS_REGION`            | `eu-west-1`              |
| `NETACEA_KINESIS_SECRET_KEY`        | `""`                     |
| `NETACEA_KINESIS_STREAM_NAME`       | `""`                     |
| `NETACEA_PROTECTION_MODE`           | `INGEST`                 |
| `NETACEA_PROTECTOR_API_URL`         | `""`                     |
| `NETACEA_REAL_IP_HEADER_INDEX`      | unset                    |
| `NETACEA_REAL_IP_HEADER`            | `""`                     |
| `NETACEA_SECRET_KEY`                | none                     |
