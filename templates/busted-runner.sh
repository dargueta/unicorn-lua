#!/bin/sh

eval "$(@LUAROCKS@ path)"
export LD_LIBRARY_PATH=@UNICORN_LIBDIR@
busted @BUSTED_CLI_ARGS@ --verbose --shuffle -f @CMAKE_CURRENT_BINARY_DIR@/busted-config.lua
