#!/bin/sh

LUA_VERSION=$1
REPO_DIR=$2

LUA_DIRNAME=lua-${LUA_VERSION}
TGZ_FILENAME=${LUA_DIRNAME}.tar.gz

set +e

mkdir -p $(dirname ${REPO_DIR})

curl -sO http://www.lua.org/ftp/${TGZ_FILENAME}
gunzip -c ${TGZ_FILENAME} > lua.tar
tar -xf lua.tar
rm lua.tar ${TGZ_FILENAME}

mv ${LUA_DIRNAME} ${REPO_DIR}

cd ${REPO_DIR}
make linux local
