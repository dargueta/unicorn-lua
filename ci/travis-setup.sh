#!/bin/bash

if [[ $TRAVIS_OS_NAME = 'windows' ]]; then
    choco install python python2 make cmake

    # Because Python 2 and 3 are installed as `python.exe` Windows can only run one of
    # them at a time. By passing an absolute path and running pip as a module, we can be
    # sure we're getting the right Python interpreter.
    /c/Python38/Python -m pip install -U -r python-requirements.txt
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
