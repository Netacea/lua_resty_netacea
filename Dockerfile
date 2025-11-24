FROM openresty/openresty:xenial

USER root

ENV HOME=/usr/src

RUN apt-get update
RUN apt-get install -y libssl-dev

RUN cd $HOME

COPY ./lua_resty_netacea-0.2-2.rockspec ./
COPY ./src ./src

RUN curl -L -o /tmp/luarocks-3.12.2-1.src.rock https://luarocks.org/luarocks-3.12.2-1.src.rock &&\
    luarocks install /tmp/luarocks-3.12.2-1.src.rock &&\
    rm /tmp/luarocks-3.12.2-1.src.rock

RUN /usr/local/openresty/luajit/bin/luarocks make ./lua_resty_netacea-0.2-2.rockspec
