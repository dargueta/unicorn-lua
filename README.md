
this is a fork from https://github.com/dargueta/unicorn-lua, use [xmake](https://xmake.io/), build with MSVC and lua5.4 on Windows

## Build

1. Install xmake https://xmake.io/#/guide/installation
2. cd unicorn-lua, and config directory
  - `xmake f --UNICORN_DIR=<UNICORN Dir> --LUA_INCDIR=<Lua Include Dir> --LUA_LIBPATH=<Path of lua54.lib>`
  - if luarocks installed, only `xmake f --UNICORN_DIR=<UNICORN Dir>`
3. `xmake`