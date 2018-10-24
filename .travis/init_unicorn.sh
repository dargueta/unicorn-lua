#!/bin/sh

REPO_DIR=$1

set +e

mkdir -p $(dirname ${REPO_DIR})

git clone --depth 1 https://github.com/unicorn-engine/unicorn.git ${REPO_DIR}

cd ${REPO_DIR}
git checkout ${UNICORN_VERSION_TAG}

./make.sh
sudo ./make.sh install
