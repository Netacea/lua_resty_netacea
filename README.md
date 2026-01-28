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

### Run development version

1. Update `./src/conf/nginx.conf` to include Netacea configuration and server configuration. Default is the NGINX instance will just return a static "Hello world" page. See "Configuration" below
2. `docker-compose up resty`
3. Access [](http://localhost:8080)

### Run tests

#### Unit tests

Without coverage report: `docker-compose run test`
With coverage report (sent to stdout) `docker-compose run -e LUACOV_REPORT=1 test [> output.html]`

#### Linter

`docker-compose run linter`

## Configuration

### nginx.conf - mitigate
```
worker_processes 1;

events {
  worker_connections 1024;
}

http {
  lua_package_path "/usr/local/share/lua/5.1/?.lua;;";
  lua_max_running_timers  2048;
  lua_max_pending_timers  4096;
  lua_socket_pool_size    1024;
  lua_need_request_body on;
  resolver 8.8.8.8 ipv6=off;
  lua_ssl_verify_depth 2;
  lua_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;
  init_worker_by_lua_block {
    netacea = (require 'lua_resty_netacea'):new({
      ingestEndpoint     = 'ingest-endpoint',
      mitigationEndpoint = 'mitigation-endpoint',
      apiKey             = 'your-api-key',
      secretKey          = 'your-secret-key',
      realIpHeader       = 'realip-header',
      ingestEnabled      = true,
      mitigationEnabled  = true,
      mitigationType     = 'MITIGATE'
    })
  }
  log_by_lua_block {
    netacea:ingest()
  }
  access_by_lua_block {
    netacea:run()
  }

  server {
    listen 80;
    server_name localhost;
    location / {
      default_type text/html;
      content_by_lua 'ngx.say("<p>hello, world</p>")';
    }
  }
}
```

### nginx.conf - inject
```
worker_processes 1;

events {
  worker_connections 1024;
}

http {
  lua_package_path "/usr/local/share/lua/5.1/?.lua;;";
  lua_max_running_timers  2048;
  lua_max_pending_timers  4096;
  lua_socket_pool_size    1024;
  lua_need_request_body on;
  resolver 8.8.8.8 ipv6=off;
  lua_ssl_verify_depth 2;
  lua_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;
  init_worker_by_lua_block {
    netacea = (require 'lua_resty_netacea'):new({
      ingestEndpoint     = 'ingest-endpoint',
      mitigationEndpoint = 'mitigation-endpoint',
      apiKey             = 'your-api-key',
      secretKey          = 'your-secret-key',
      realIpHeader       = 'realip-header',
      ingestEnabled      = true,
      mitigationEnabled  = true,
      mitigationType     = 'INJECT'
    })
  }
  log_by_lua_block {
    netacea:ingest()
  }
  access_by_lua_block {
    netacea:run()
  }

  server {
    listen 80;
    server_name localhost;
    location / {
      default_type text/html;
      content_by_lua 'ngx.say("<p>hello, world</p>")';
    }
  }
}
```
