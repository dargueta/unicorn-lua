import ctypes
import logging
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import urllib.request

logging.basicConfig(level=logging.INFO)

UNIX_SCRIPT = """
git clone --depth 1 https://github.com/unicorn-engine/unicorn.git unicorn-{version}
cd unicorn-{version}
git fetch --all --tags --prune
git checkout {version}
./make.sh
sudo ./make.sh install
"""

UNICORN_VERSION = sys.argv[1]
WINDOWS_URL_TEMPLATE = "https://github.com/unicorn-engine/unicorn/releases/download/{version}/unicorn-{version}-win{bits}.zip"


def install_unixlike():
    """Installation for *NIX systems like Ubuntu and MacOS."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        subprocess.run(
            ["/bin/sh", "-e", "-c", UNIX_SCRIPT.format(version=UNICORN_VERSION)],
            cwd=tmp_dir,
            check=True,
        )


def get_windows_system_install_dir():
    buf = ctypes.create_string_buffer(b"\x00" * 256)
    ctypes.windll.kernel32.GetSystemDirectoryA(buf, 256)
    directory = buf.value.decode("ascii")
    logging.info("Found Windows DLL installation directory: %r", directory)
    return directory


def install_windows():
    """Install Unicorn on Windows"""
    if sys.maxsize > 2 ** 32:
        bits = 64
    else:
        bits = 32

    url = WINDOWS_URL_TEMPLATE.format(version=UNICORN_VERSION, bits=bits)
    response = urllib.request.urlopen(url)
    if response.status != 200:
        logging.error(
            "Downloading `%s` failed: HTTP %d: %s",
            url,
            response.status,
            response.reason,
        )
        return sys.exit(1)

    with tempfile.TemporaryDirectory() as tmp_dir:
        archive_file_path = os.path.join(tmp_dir, "__archive.zip")
        with open(archive_file_path, "wb") as fd:
            shutil.copyfileobj(response, fd, 2 ** 20)

        # Unpack the zip archive into a vaguely reasonable directory. This contains the
        # DLL and header files.
        os.makedirs("C:\\Program Files\\UnicornEngine")
        shutil.unpack_archive(archive_file_path, "C:\\Program Files\\UnicornEngine")

        # Put the DLL where Windows can find it
        shutil.move(
            "C:\\Program Files\\UnicornEngine\\unicorn.dll",
            get_windows_system_install_dir(),
        )


def main():
    if sys.platform in ("win32", "cygwin"):
        install_windows()
    else:
        install_unixlike()


if __name__ == "__main__":
    main()
