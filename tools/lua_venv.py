#!/usr/bin/env python3

"""Script for downloading and installing Lua and LuaRocks."""

import argparse
import configparser
import json
import logging
import os
import re
import shutil
import subprocess
import zipfile

import sys
import tempfile
from urllib import request


LOG = logging.getLogger(__name__)
HERE = os.path.dirname(__file__)

CONFIG = configparser.ConfigParser(interpolation=None)
CONFIG.read(os.path.join(HERE, "lua_settings.ini"))

SUPPORTED_LUA_VERSIONS = tuple(CONFIG["supported_versions"].keys())
SPECIFIC_VERSIONS = CONFIG["specific_versions"]
LUAROCKS_VERSION = CONFIG["luarocks"]["default_version"]


class ErrorExit(RuntimeError):
    """An exception to throw when a fatal error occurs."""


def download_lua(args, download_dir):
    """Download the Lua tarball to the specified directory."""
    full_version = CONFIG["specific_versions"][args.lua_version]

    if args.lua_version.startswith("luajit"):
        LOG.info("Downloading LuaJIT %s into `%s`...", full_version, download_dir)
        response = request.urlopen(
            "https://luajit.org/download/LuaJIT-%s.tar.gz" % full_version
        )
    else:
        # Normal Lua
        LOG.info("Downloading Lua %s into `%s`...", full_version, download_dir)
        response = request.urlopen(
            "https://www.lua.org/ftp/lua-%s.tar.gz" % full_version
        )

    if response.status != 200:
        raise ErrorExit(
            "Lua download failed: HTTP %d: %s" % (response.status, response.reason)
        )

    output_file = os.path.join(download_dir, "lua.tar.gz")
    with open(output_file, "wb") as fd:
        shutil.copyfileobj(response, fd)
    return output_file


def configure_lua(args, extract_dir):
    """Customize Lua before building it.

    Before building normal Lua we need to change where it looks for installed libraries.
    This way we can determine the directory to install the built Unicorn binding with
    one command, without worrying if we're using a virtual environment or not.

    Arguments:
        args: The parsed command line arguments.
        extract_dir:
            The path to the directory where the Lua tarball was extracted.
    """
    # We don't need to modify any LuaJIT files, as we can do it all in the Make command.
    if args.lua_version.startswith("luajit"):
        return

    with open(os.path.join(extract_dir, "src", "luaconf.h"), "r+") as fd:
        luaconf_contents = fd.read()
        luaconf_contents = re.sub(
            r"#define\s+LUA_ROOT[^\\n]*\\n",
            r'#define LUA_ROOT "%s"\n' % args.install_to,
            luaconf_contents,
        )
        fd.seek(0)
        fd.truncate(0)
        fd.write(luaconf_contents)


def compile_lua(args, lua_platform, _tarball_path, extract_dir):
    """Compile Lua.

    Arguments:
        args: The parsed command line arguments.
        lua_platform:
            The string that tells Lua what platform to compile for, e.g. "linux",
            "posix", "generic", etc. See the Lua documentation for what values are
            supported.
        extract_dir:
            The path to the directory where the Lua tarball was extracted to. This must
            contain the main Makefile.

    Returns:
        A dict containing information about the Lua installation, such as where the
        binary will be installed at, where the headers are, where the library search
        directory is, and so on.
    """
    install_to = os.path.abspath(os.path.normpath(args.install_to))

    if args.lua_version.startswith("luajit"):
        run_args = ["amalg", "PREFIX=" + install_to]
    else:
        run_args = [lua_platform, "local"]

    result = subprocess.run(
        ["make", "-C", extract_dir] + run_args,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        universal_newlines=True,
    )
    if result.returncode != 0:
        LOG.error("Compilation failed.")
        raise ErrorExit(result.stdout)

    if args.lua_version.startswith("luajit"):
        short_version = args.lua_version[6:]
        return {
            "lua_root": install_to,
            "lua_exe": os.path.join(install_to, "bin", "luajit"),
            "lua_include": os.path.join(
                install_to, "include", "luajit-" + short_version
            ),
            "lua_lib": os.path.join(install_to, "lib", "libluajit-5.1.a"),
            "is_luajit": True,
            "lua_short_version": "5.1",
        }

    # else: Regular Lua
    return {
        "lua_root": install_to,
        "lua_exe": os.path.join(install_to, "bin", "lua"),
        "lua_include": os.path.join(install_to, "include"),
        "lua_lib": os.path.join(install_to, "lib", "liblua.a"),
        "is_luajit": False,
        "lua_short_version": args.lua_version.rpartition(".")[0],
    }


def install_lua(lua_version, install_to, extract_dir):
    """Install Lua which has already been compiled.

    Arguments:
        lua_version:
            The version of Lua to install, as passed in on the command line. This is not
            the "specific" version.
        install_to:
            The path to the directory where Lua is to be installed. May be a relative
            path. See the Lua documentation for the exact directory structure created
            here.
        extract_dir:
            A path to the directory where the Lua tarball was extracted to. The Makefile
            must be in here.
    """
    install_to = os.path.abspath(os.path.normpath(install_to))

    if lua_version.startswith("luajit"):
        run_args = ["PREFIX=" + install_to]
    else:
        run_args = ["INSTALL_TOP=" + install_to]

    result = subprocess.run(
        ["make", "-C", extract_dir, "install"] + run_args,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        universal_newlines=True,
    )
    if result.returncode != 0:
        LOG.error("Installation failed.")
        raise ErrorExit(result.stdout)


########################################################################################
# LuaRocks stuff


def download_luarocks_linux(download_dir):
    response = request.urlopen(
        "https://luarocks.org/releases/luarocks-%s.tar.gz" % LUAROCKS_VERSION
    )
    if response.status != 200:
        raise ErrorExit(
            "LuaRocks download failed: HTTP %d: %s" % (response.status, response.reason)
        )

    output_file = os.path.join(download_dir, "luarocks.tar.gz")
    with open(output_file, "wb") as fd:
        shutil.copyfileobj(response, fd)
    return output_file


def download_luarocks_windows(download_dir):
    if sys.maxsize > 2**32:
        bits = 64
    else:
        bits = 32

    response = request.urlopen(
        "http://luarocks.github.io/luarocks/releases/luarocks-%s-windows-%d.zip"
        % (LUAROCKS_VERSION, bits)
    )
    if response.status != 200:
        raise ErrorExit(
            "LuaRocks download failed: HTTP %d: %s" % (response.status, response.reason)
        )

    output_file = os.path.join(download_dir, "luarocks.zip")
    with open(output_file, "wb") as fd:
        shutil.copyfileobj(response, fd)
    return output_file


def download_luarocks(download_dir):
    if sys.platform == "win32":
        return download_luarocks_windows(download_dir)
    return download_luarocks_linux(download_dir)


def install_luarocks_linux(lua_path_info, install_to, extract_dir):
    LOG.info("Configuring LuaRocks")
    result = subprocess.run(
        [
            os.path.join(extract_dir, "configure"),
            "--prefix=" + install_to,
            "--with-lua=" + lua_path_info["lua_root"],
            "--with-lua-include=" + lua_path_info["lua_include"],
            "--force-config",
        ],
        cwd=extract_dir,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        universal_newlines=True,
    )
    if result.returncode != 0:
        LOG.error("Failed to configure LuaRocks.")
        raise ErrorExit(result.stdout)

    LOG.info("Bootstrapping LuaRocks installation")
    result = subprocess.run(
        ["make", "-C", extract_dir, "bootstrap"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        universal_newlines=True,
    )
    if result.returncode != 0:
        LOG.error("Failed to install LuaRocks.")
        raise ErrorExit(result.stdout)


def install_luarocks_windows(lua_path_info, install_to, extract_dir):
    LOG.info("Configuring LuaRocks")
    zip_file_path = os.path.join(extract_dir, "luarocks.zip")
    luarocks_path = os.path.join(install_to, "luarocks.exe")
    with zipfile.ZipFile(zip_file_path, "r") as archive:
        with archive.open("luarocks.exe", "rb") as source_fd:
            with open(luarocks_path, "wb") as out_fd:
                shutil.copyfileobj(source_fd, out_fd, 2**24)

    result = subprocess.run(
        [
            luarocks_path,
            "config",
            "--lua-version",
            lua_path_info["lua_short_version"],
            "lua_dir",
            lua_path_info["lua_root"],
            "--with-lua-include=" + lua_path_info["lua_include"],
            "--force-config",
        ],
        cwd=extract_dir,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        universal_newlines=True,
    )
    if result.returncode != 0:
        LOG.error("Failed to configure LuaRocks.")
        raise ErrorExit(result.stdout)

    LOG.info("Bootstrapping LuaRocks installation")
    result = subprocess.run(
        ["make", "-C", extract_dir, "bootstrap"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        universal_newlines=True,
    )
    if result.returncode != 0:
        LOG.error("Failed to install LuaRocks.")
        raise ErrorExit(result.stdout)


def install_luarocks(lua_path_info, install_to, extract_dir):
    if sys.platform == "win32":
        return install_luarocks_windows(lua_path_info, install_to, extract_dir)
    return install_luarocks_linux(lua_path_info, install_to, extract_dir)


def get_luarocks_paths(luarocks_exe):
    """Get the paths where LuaRocks installs C libraries and Lua files.

    Arguments:
        luarocks_exe: The path to the LuaRocks executable. May be relative.

    Returns:
        A dictionary with two keys: `LUAROCKS_CPATH` and `LUAROCKS_LPATH`. These point
        to the directories where LuaRocks installs C libraries and libraries written in
        pure Lua, respectively.
    """
    luarocks_exe = os.path.abspath(luarocks_exe)
    result = subprocess.run(
        [luarocks_exe, "path", "--lr-path"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
    )
    if result.returncode != 0:
        LOG.error("Failed to pull LuaRocks library path.")
        raise ErrorExit(result.stderr)

    lpath = result.stdout.strip()

    result = subprocess.run(
        [luarocks_exe, "path", "--lr-cpath"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
    )
    if result.returncode != 0:
        LOG.error("Failed to pull LuaRocks C library path.")
        raise ErrorExit(result.stderr)

    return {"luarocks_lpath": lpath, "luarocks_cpath": result.stdout.strip()}


########################################################################################
# Main stuff


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-o",
        "--config-out",
        help="Write file locations and other information to this file for use by the"
        " `configure` script. If not given, results are written to STDOUT.",
        metavar="PATH",
    )
    parser.add_argument(
        "-l",
        "--luarocks",
        action="store_true",
        help="Install LuaRocks as well. It'll be configured to work with this specific"
        " Lua installation and won't interfere with other installations of LuaRocks.",
    )
    parser.add_argument(
        "lua_version",
        metavar="VERSION",
        choices=SUPPORTED_LUA_VERSIONS,
        help="The version of Lua to download and install. Valid choices are: "
        + ", ".join(repr(v) for v in sorted(CONFIG.options("supported_versions"))),
    )
    parser.add_argument(
        "install_to",
        metavar="INSTALL_PATH",
        help="The directory to install Lua into. It'll be created if it doesn't already"
        " exist.",
    )
    return parser.parse_args()


def main():
    logging.basicConfig(format="[%(levelname)-8s] %(message)s", level=logging.INFO)
    lua_platform = CONFIG["platform_targets"][sys.platform]
    if not lua_platform:
        LOG.warning("OS platform potentially unsupported: %s", sys.platform)
        lua_platform = "generic"

    args = parse_args()
    with tempfile.TemporaryDirectory() as download_dir:
        LOG.info("Downloading Lua %s ...", args.lua_version)
        tarball_path = download_lua(args, download_dir)

        if args.lua_version.startswith("luajit"):
            extract_dir = os.path.join(
                download_dir, "LuaJIT-" + SPECIFIC_VERSIONS[args.lua_version]
            )
        else:
            extract_dir = os.path.join(
                download_dir, "lua-" + SPECIFIC_VERSIONS[args.lua_version]
            )

        LOG.info("Extracting `%s` into `%s` ...", tarball_path, extract_dir)
        shutil.unpack_archive(tarball_path, download_dir, "gztar")

        LOG.info("Configuring compilation options ...")
        configure_lua(args, extract_dir)

        LOG.info("Compiling ...")
        path_info = compile_lua(args, lua_platform, tarball_path, extract_dir)

        install_to = os.path.abspath(os.path.normpath(args.install_to))
        LOG.info("Installing to `%s` ...", install_to)
        # Ensure the installation location exists before we try installing there.
        os.makedirs(install_to, exist_ok=True)
        install_lua(args.lua_version, install_to, extract_dir)

        configuration_variables = path_info.copy()
        configuration_variables["lua_short_version"] = args.lua_version
        configuration_variables["virtualenv_dir"] = install_to
        configuration_variables["lua_full_version"] = SPECIFIC_VERSIONS[
            args.lua_version
        ]

    if args.luarocks:
        with tempfile.TemporaryDirectory() as download_dir:
            LOG.info("Downloading LuaRocks %s ...", LUAROCKS_VERSION)
            tarball_path = download_luarocks(download_dir)

            extract_dir = os.path.join(download_dir, "luarocks-" + LUAROCKS_VERSION)

            LOG.info("Extracting `%s` into `%s` ...", tarball_path, extract_dir)
            shutil.unpack_archive(tarball_path, download_dir, "gztar")

            luarocks_install_to = os.path.join(install_to, "luarocks")
            LOG.info("Installing LuaRocks into `%s` ...", luarocks_install_to)
            os.makedirs(luarocks_install_to, exist_ok=True)
            install_luarocks(path_info, luarocks_install_to, extract_dir)

            LOG.info("Pulling LuaRocks path information ...")
            luarocks_paths = get_luarocks_paths(
                os.path.join(luarocks_install_to, "bin", "luarocks")
            )

            configuration_variables.update(luarocks_paths)
            configuration_variables["luarocks_exe"] = os.path.join(
                luarocks_install_to, "bin", "luarocks"
            )
            configuration_variables["luarocks_version"] = LUAROCKS_VERSION
    else:
        LOG.info("Not installing LuaRocks.")

    if args.config_out:
        LOG.info("Writing configuration variables to `%s` ...", args.config_out)
        with open(args.config_out, "w") as fd:
            json.dump(configuration_variables, fd, indent=2)
    else:
        print(json.dumps(configuration_variables, indent=2))


if __name__ == "__main__":
    try:
        main()
    except ErrorExit as error:
        LOG.error(str(error))
        sys.exit(1)
    except KeyboardInterrupt:
        LOG.warning("Killed by the user.")
    sys.exit(0)
