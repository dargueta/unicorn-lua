# NOTE: This will break the builds when Travis changes the version(s) of Python they
# have installed.
if [[ $TRAVIS_OS_NAME = 'linux' ]]; then
    pyenv local 2.7.15 3.7.1
fi

if [[ $TRAVIS_OS_NAME = 'windows' ]]; then
    choco install -y python3 python2 make cmake
    /c/Python38/Python -m pip install -U -r python-requirements.txt
else
    pip3 install -U -r python-requirements.txt
fi
