FROM openresty/openresty:xenial AS base

USER root

WORKDIR /usr/src
# ENV HOME=/usr/src

RUN apt-get update
RUN apt-get install -y libssl-dev

# RUN cd $HOME

RUN curl -L -o /tmp/luarocks-3.12.2-1.src.rock https://luarocks.org/luarocks-3.12.2-1.src.rock &&\
    luarocks install /tmp/luarocks-3.12.2-1.src.rock &&\
    rm /tmp/luarocks-3.12.2-1.src.rock


FROM base AS build
COPY ./lua_resty_netacea-0.2-2.rockspec ./
COPY ./src ./src
RUN /usr/local/openresty/luajit/bin/luarocks make ./lua_resty_netacea-0.2-2.rockspec

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
