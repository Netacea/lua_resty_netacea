# lua_resty_netacea
An Openresty module for easy integration of Netacea services

# Running Tests
`docker-compose build` then `docker-compose run test`

## nginx.conf - mitigate
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
      mitigationEnabled  = true
    })
  }
  log_by_lua_block {
    netacea:ingest()
  }
  access_by_lua_block {
    netacea:mitigate()
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

## nginx.conf - inject
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
      mitigationEnabled  = true
    })
  }
  log_by_lua_block {
    netacea:ingest()
  }
  access_by_lua_block {
    netacea:inject()
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
