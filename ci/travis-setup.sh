#!/bin/bash

if [[ $TRAVIS_OS_NAME = 'windows' ]]; then
    choco install python python2 make cmake

    # Because Python 2 and 3 are installed as `python.exe` Windows can only run one of
    # them at a time. Python 3 needs to be first on the search path, and can only be
    # referred to as `python` not `python3`. It also can't find `pip` so we have to use
    # the indirect way of running it.
    export PATH="/c/Python37:/c/Python37/Scripts:$PATH"
    python -m pip install -U -r python-requirements.txt
fi

# NOTE: This will break the builds when Travis changes the version(s) of Python they
# have installed.
if [[ $TRAVIS_OS_NAME = 'linux' ]]; then
    pyenv local 2.7.15 3.7.1
    pip3 install -U -r python-requirements.txt
fi

if [[ $TRAVIS_OS_NAME = 'osx' ]]; then
    pip3 install -U -r python-requirements.txt
fi
