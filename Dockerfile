FROM openresty/openresty:noble AS base

USER root

WORKDIR /usr/src

RUN apt-get update
RUN apt-get install -y libssl-dev


FROM base AS build
COPY ./lua_resty_netacea-1.0-0.rockspec ./
COPY ./src ./src
RUN /usr/local/openresty/luajit/bin/luarocks make ./lua_resty_netacea-1.0-0.rockspec

FROM build AS test

RUN /usr/local/openresty/luajit/bin/luarocks install busted
RUN /usr/local/openresty/luajit/bin/luarocks install luacov
RUN /usr/local/openresty/luajit/bin/luarocks install cluacov
RUN /usr/local/openresty/luajit/bin/luarocks install require
RUN /usr/local/openresty/luajit/bin/luarocks install luacheck

COPY ./test ./test
COPY ./run_lua_tests.sh ./run_lua_tests.sh
RUN chmod +x ./run_lua_tests.sh

CMD ["bash", "-c", "./run_lua_tests.sh"]

FROM test AS lint

CMD ["bash", "-c", "luacheck --no-self -- ./src"]
