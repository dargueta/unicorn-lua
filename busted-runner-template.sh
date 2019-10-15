#!/bin/sh

eval "@LUAROCKS_EXE@ path"
@BUSTED_EXE@ @BUSTED_CLI_ARGS@ -f @LUA_INSTALL_DIR@/busted-configuration.lua
