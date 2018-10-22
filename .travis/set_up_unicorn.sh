#!/bin/bash

git clone --depth 1 https://github.com/unicorn-engine/unicorn.git
cd unicorn
git checkout $UNICORN_VERSION_TAG
./make.sh
sudo ./make.sh install
