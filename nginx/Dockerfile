FROM openresty/openresty:jammy

# Install LuaRocks and required dev tools
RUN apt-get update && \
    apt-get install -y --no-install-recommends luarocks git && \
    luarocks install lua-resty-http && \
    luarocks install lua-resty-jwt && \
    luarocks install lua-cjson && \
    luarocks install lua-resty-string && \
    luarocks install lua-resty-rsa && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Copy Nginx config and Lua scripts
COPY nginx.conf /usr/local/openresty/nginx/conf/nginx.conf
COPY lua/ /etc/nginx/lua/

EXPOSE 8080
CMD ["openresty", "-g", "daemon off;"]
