#!/bin/bash

set -euvx

UNICORN_VERSION=$1

git clone --depth 1 https://github.com/unicorn-engine/unicorn.git unicorn-${UNICORN_VERSION}
cd unicorn-${UNICORN_VERSION}
git fetch --all --tags --prune
git checkout ${UNICORN_VERSION}

# 2.x has a different installation process than 1.x
if echo "$UNICORN_VERSION" | grep '^2\.' 1>/dev/null; then
  # Unicorn 2.x
  mkdir build
  cd build
  cmake .. -DCMAKE_BUILD_TYPE=Release
  sudo make install
else
  ./make.sh
  sudo ./make.sh install
fi
