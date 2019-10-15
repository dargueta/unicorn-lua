cmake_minimum_required(VERSION 3.8 FATAL_ERROR)
project(UnicornLua VERSION 0.1 LANGUAGES CXX)

# Created by the configuration script
include("configuration.cmake.txt")


if (NOT DEFINED ARCHITECTURE_SLUGS)
    set(ARCHITECTURE_SLUGS arm;arm64;mips;m68k;sparc;x86)
endif()


set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_PLATFORM_INDEPENDENT_CODE ON)

find_package(Python3 REQUIRED)


if(USE_VIRTUALENV)
    message(STATUS "Downloading and extracting Lua...")
    file(
        DOWNLOAD
        "https://www.lua.org/ftp/lua-${LUA_FULL_VERSION}.tar.gz"
        "${CMAKE_CURRENT_BINARY_DIR}/lua-${LUA_FULL_VERSION}.tar.gz"
    )
    execute_process(
        COMMAND cmake -E tar -xz "${CMAKE_CURRENT_BINARY_DIR}/lua-${LUA_FULL_VERSION}.tar.gz"
        WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
    )

    set(LUA_DOWNLOAD_DIR "${CMAKE_CURRENT_BINARY_DIR}/lua-${LUA_FULL_VERSION}")
    set(LUA_ROOT "${LUA_DOWNLOAD_DIR}/install")

    # Before building Lua we need to change where it looks for installed libraries. This
    # way, we can determine the directory to install the built Unicorn binding with a
    # single command, without worrying if we're using a virtual environment or not.
    message(STATUS "Configuring Lua...")
    file(READ "${LUA_DOWNLOAD_DIR}/src/luaconf.h" LUACONF_H_CONTENTS)
    string(
        REGEX REPLACE
        "#define[ \t]+LUA_ROOT[^\n]+\n" "#define LUA_ROOT \"${LUA_ROOT}/\"\n"
        MODIFIED_LUACONF_H_CONTENTS
        "${LUACONF_H_CONTENTS}"
    )
    file(WRITE "${LUA_DOWNLOAD_DIR}/src/luaconf.h" "${MODIFIED_LUACONF_H_CONTENTS}")

    message(STATUS "Building Lua and installing to: ${LUA_ROOT}")
    execute_process(
        COMMAND make -C "${LUA_DOWNLOAD_DIR}" "MYCFLAGS=\"-fPIC\"" "${DETECTED_LUA_PLATFORM}" local
        OUTPUT_QUIET
    )

    set(LUA_EXE "${LUA_ROOT}/bin/lua")
    set(LUA_HEADERS_PATH "${LUA_ROOT}/include")
    set(LUA_LIBRARY "${LUA_ROOT}/lib/liblua.a")
    set(LUAROCKS_DOWNLOAD_DIR "${CMAKE_CURRENT_BINARY_DIR}/luarocks-${LUAROCKS_VERSION}")
    set(LUAROCKS_INSTALL_DIR "${LUAROCKS_DOWNLOAD_DIR}-installation")

    message(STATUS "Downloading and extracting LuaRocks...")
    file(
        DOWNLOAD
        https://luarocks.org/releases/luarocks-${LUAROCKS_VERSION}.tar.gz
        "${CMAKE_CURRENT_BINARY_DIR}/luarocks-${LUAROCKS_VERSION}.tar.gz"
    )
    execute_process(
        COMMAND cmake -E tar -xz "${CMAKE_CURRENT_BINARY_DIR}/luarocks-${LUAROCKS_VERSION}.tar.gz"
        WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
    )

    message(STATUS "Building LuaRocks...")
    execute_process(
        COMMAND sh "${LUAROCKS_DOWNLOAD_DIR}/configure"
                   "--prefix=${LUAROCKS_INSTALL_DIR}"
                   "--lua-version=${LUA_SHORT_VERSION}"
                   "--with-lua=${LUA_ROOT}"
                   "--force-config"
        WORKING_DIRECTORY "${LUAROCKS_DOWNLOAD_DIR}"
    )

    message(STATUS "Installing LuaRocks to: ${LUAROCKS_INSTALL_DIR}")
    execute_process(
        COMMAND make -C "${LUAROCKS_DOWNLOAD_DIR}" bootstrap
        OUTPUT_QUIET
    )

    set(LUAROCKS_EXE "${LUAROCKS_INSTALL_DIR}/bin/luarocks")
else()
    find_library(LUA_LIBRARY NAMES lua liblua)
    find_path(LUA_HEADERS_PATH NAMES lua.h)
    find_program(
        LUA_EXE
        NAMES lua
        DOC "The Lua interpreter"
    )
    find_program(
        LUAROCKS_EXE
        NAMES luarocks
        DOC "Luarocks installation program"
    )
endif()


execute_process(
    COMMAND ${LUAROCKS_EXE} path --lr-path
    OUTPUT_VARIABLE LUAROCKS_LPATH
    OUTPUT_STRIP_TRAILING_WHITESPACE
)
execute_process(
    COMMAND ${LUAROCKS_EXE} path --lr-cpath
    OUTPUT_VARIABLE LUAROCKS_CPATH
    OUTPUT_STRIP_TRAILING_WHITESPACE
)
execute_process(
    COMMAND ${LUA_EXE} -e "print(string.match('${LUAROCKS_CPATH}', '^([^?]+)'))"
    OUTPUT_VARIABLE LUA_INSTALL_DIR
    OUTPUT_STRIP_TRAILING_WHITESPACE
)

message(STATUS "Installing required rocks...")
execute_process(
    COMMAND ${LUAROCKS_EXE} install busted lcurses
    OUTPUT_QUIET
)

get_filename_component(LUAROCKS_BIN_DIR "${LUAROCKS_EXE}" DIRECTORY)
set(BUSTED_EXE "${LUAROCKS_BIN_DIR}/busted")

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~ Define dependencies ~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

find_library(UNICORN_LIBRARY NAMES unicorn libunicorn)
find_path(UNICORN_HEADERS_PATH unicorn/unicorn.h)
if (UNICORN_HEADERS_PATH STREQUAL "UNICORN_HEADERS_PATH-NOTFOUND")
    message(FATAL_ERROR "Unicorn doesn't appear to be installed, or the headers are in a non-standard location.")
endif()

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Define targets ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

add_subdirectory("src" "${CMAKE_CURRENT_BINARY_DIR}/lib")               # Library code
add_subdirectory("tests/c" "${CMAKE_CURRENT_BINARY_DIR}/tests_c")       # Tests with C++ code
add_subdirectory("tests/lua" "${CMAKE_CURRENT_BINARY_DIR}/tests_lua")   # Tests with Lua code
