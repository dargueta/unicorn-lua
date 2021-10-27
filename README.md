
this is a fork from https://github.com/dargueta/unicorn-lua, use [xmake](https://xmake.io/), build with MSVC and lua5.4 on Windows

## Build

requirements:
- python: to run tools/generate_constants.py
- xmake: to build

steps:
1. CD to unicorn-lua, and config the directory `xmake f --UNICORN_DIR=<UNICORN-Directory>`
2. Execute `xmake`