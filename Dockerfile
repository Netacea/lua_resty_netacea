FROM openresty/openresty:xenial

LABEL author="Curtis Johnson <curtis.johnson@netacea.com>"
LABEL maintainer="Curtis Johnson <curtis.johnson@netacea.com>"

USER root

ENV HOME=/usr/src

RUN apt-get update
RUN apt-get install -y libssl-dev

RUN cd $HOME

COPY ./lua_resty_netacea-0.0-1.rockspec ./
COPY ./src ./src

RUN /usr/local/openresty/luajit/bin/luarocks make ./lua_resty_netacea-0.0-1.rockspec
