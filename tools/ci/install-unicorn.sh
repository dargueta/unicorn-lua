#!/bin/bash

set -euvx

UNICORN_VERSION=$1

git clone --depth 1 https://github.com/unicorn-engine/unicorn.git unicorn-${UNICORN_VERSION}
cd unicorn-${UNICORN_VERSION}
git fetch --all --tags --prune
git checkout ${UNICORN_VERSION}
./make.sh
sudo ./make.sh install
