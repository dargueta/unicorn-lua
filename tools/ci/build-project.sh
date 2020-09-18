#!/bin/bash

set -ev


LUA_VERSION=$1

python3 ./tools/lua_venv.py -l --config-out settings.json $LUA_VERSION __lua${LUA_VERSION}
python3 ./configure --venv-config settings.json
mkdir build
cd build
cmake -DCMAKE_VERBOSE_MAKEFILE=YES ..
make
