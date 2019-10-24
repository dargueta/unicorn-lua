set -e

if [[ $TRAVIS_OS_NAME = 'windows' ]]; then
    # Install pre-built binaries on Windows
    wget --tries=3 https://github.com/unicorn-engine/unicorn/releases/download/${UNICORN_VERSION}/unicorn-${UNICORN_VERSION}-win64.zip
    unzip -b unicorn-${UNICORN_VERSION}-win64.zip
    sudo mv unicorn-${UNICORN_VERSION}-win64/*.dll /c/Windows
else
  # Build from source on OSX and Linux
  wget --tries=3 https://github.com/unicorn-engine/unicorn/archive/${UNICORN_VERSION}.zip
  unzip -b ${UNICORN_VERSION}.zip
  pushd unicorn-${UNICORN_VERSION}
  ./make.sh
  sudo ./make.sh install
  popd
fi
