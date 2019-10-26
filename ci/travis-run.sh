set -e

if [[ $TRAVIS_OS_NAME = 'windows' ]]; then
    # This will break when the version installed by Chocolatey changes. We need to figure
    # out how to point `python3` to the executable. `alias` doesn't seem to work.
    /c/Python38/Python ./configure --venv-version $LUA_VERSION
else
    python3 ./configure --venv-version $LUA_VERSION
fi

mkdir build
pushd build
cmake -DCMAKE_VERBOSE_MAKEFILE=YES ..
make
ctest --output-on-failure
popd
