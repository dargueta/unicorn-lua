"""Install Unicorn on Windows"""

import ctypes
import logging
import os
import shutil
import sys
import tempfile
import urllib.request

logging.basicConfig(level=logging.INFO)

ARCHIVE_DIRECTORY = "unicorn-{version}-win{bits}"
WINDOWS_URL_TEMPLATE = "https://github.com/unicorn-engine/unicorn/releases/download/{version}/unicorn-{version}-win{bits}.zip"

# This is where LuaRocks expects the headers to be. The other possible location is
# C:\external but for some reason that doesn't seem to work on the CI machines.
HEADERS_DIR = "C:\\Windows\\System32"


def get_windows_system_install_dir():
    # type: () -> str
    """Get the directory where we should install the Unicorn DLL.

    See: https://docs.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya
    """
    buf = ctypes.create_string_buffer(b"\x00" * 256)
    ctypes.windll.kernel32.GetSystemDirectoryA(buf, 256)
    directory = buf.value.decode("ascii")
    logging.info("Found Windows DLL installation directory: %r", directory)
    return directory


def get_app_data_dir():
    # type: () -> str
    """Get the directory where we're going to put the header files.

    For the sake of simplicity we'll create a directory called "UnicornEngine" in the
    "Program Files" directory. We can't assume this is on C: and we don't know if the
    system defines a different directory, so we can't hardcode it.
    """
    root = os.getenv("LOCALAPPDATA")
    if root is None:
        root = tempfile.gettempdir()
        logging.error(
            "LOCALAPPDATA environment variable is empty, falling back to %r", root
        )
    root = os.path.abspath(root)
    return os.path.join(root, "UnicornEngine")


def main():
    # type: () -> None
    if len(sys.argv) != 2:
        logging.error("Expected one argument, the exact version of Unicorn to install.")
        sys.exit(1)

    if sys.maxsize > 2**32:
        bits = 64
    else:
        bits = 32

    unicorn_version = sys.argv[1]
    url = WINDOWS_URL_TEMPLATE.format(version=unicorn_version, bits=bits)

    logging.info("Downloading Unicorn archive from: %s", url)
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
        logging.info("Copying archive to temporary directory: %s", tmp_dir)
        archive_file_path = os.path.join(tmp_dir, "__archive.zip")
        with open(archive_file_path, "wb") as fd:
            shutil.copyfileobj(response, fd, 2**20)

        # Unpack the zip archive into a vaguely reasonable directory. This contains the
        # DLL and header files.
        data_dir = get_app_data_dir()

        logging.info("Creating installation directory: %s", data_dir)
        os.makedirs(data_dir)

        logging.info(
            "Unpacking archive to data directory: %s -> %s", archive_file_path, data_dir
        )
        shutil.unpack_archive(archive_file_path, data_dir)

        logging.info("(DEBUG) TMPDIR tree at %s: %s", data_dir, os.listdir(data_dir))

        unpacked_directory = os.path.join(
            data_dir, ARCHIVE_DIRECTORY.format(version=unicorn_version, bits=bits)
        )

        # Put the libraries where Windows can find them
        for filename in ("unicorn.dll", "unicorn.lib"):
            lib_path = os.path.join(unpacked_directory, filename)
            target_dir = get_windows_system_install_dir()
            logging.info(
                "Moving library to Windows directory: %s -> %s", lib_path, target_dir
            )
            shutil.move(lib_path, target_dir)

        # Move the headers over as well
        target_headers_dir = HEADERS_DIR.format(version=unicorn_version, bits=bits)
        os.makedirs(target_headers_dir, exist_ok=True)
        source_headers_dir = os.path.join(unpacked_directory, "include")
        logging.info("Moving headers: %s -> %s", source_headers_dir, target_headers_dir)
        shutil.move(source_headers_dir, target_headers_dir)


if __name__ == "__main__":
    main()
