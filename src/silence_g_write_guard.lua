-- Some QOL patches for warnings from g_write_guard.
-- See https://github.com/openresty/lua-nginx-module/issues/1558#issuecomment-512360451
rawset(_G, 'lfs', false) -- silence g_write_guard about lfs module in busted