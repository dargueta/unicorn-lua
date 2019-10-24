set +e

git clone --depth 1 https://github.com/unicorn-engine/unicorn.git unicorn-${UNICORN_VERSION}
pushd unicorn-${UNICORN_VERSION}
git fetch --all --tags --prune
git checkout ${UNICORN_VERSION}

if [[ $TRAVIS_OS_NAME = 'windows' ]]; then
    # TODO
else
  ./make.sh
  sudo ./make.sh install
  popd
fi
