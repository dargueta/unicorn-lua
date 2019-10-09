cmake_minimum_required(VERSION 3.8 FATAL_ERROR)
project(UnicornLua VERSION 0.1 LANGUAGES CXX)

# SHOULD BE SET BY THE CONFIGURE SCRIPT
set(LUA_FULL_VERSION 5.3.5)
set(LUA_SHORT_VERSION 5.3)
set(USING_VENV ON)
set(IS_LUAJIT OFF)
# </PREDEFINED>

if (NOT DEFINED ARCHITECTURE_SLUGS)
    set(ARCHITECTURE_SLUGS arm;arm64;mips;m68k;sparc;x86)
endif()

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_PLATFORM_INDEPENDENT_CODE ON)

find_package(Python3 REQUIRED)

find_library(UNICORN_LIBRARY NAMES unicorn libunicorn)
find_library(PTHREADS_LIBRARY NAMES pthread libpthread)
find_program(
    LENV_EXE
    NAMES lenv
    HINTS $ENV{HOME}/.lenv/bin
    DOC "Program for setting the Lua environment"
)

if (USING_VENV)
    if (LENV_EXE STREQUAL "LENV_EXE-NOTFOUND")
        message(FATAL_ERROR "Can't find lenv script. Have you installed it?")
    endif()
    find_path(
        LENV_ROOT_DIRECTORY
        NAMES .lenv
        HINTS ENV HOME
        DOC "Root directory where lenv environment manager is stored"
    )

    if (IS_LUAJIT)
        set(
            LENV_LUA_ROOT
            "${LENV_ROOT_DIRECTORY}/.lenv/luajit/${LUAJIT_FULL_VERSION}"
            CACHE INTERNAL "Root directory for Lua environment installation."
        )
    else()
        set(
            LENV_LUA_ROOT
            "${LENV_ROOT_DIRECTORY}/.lenv/lua/${LUA_FULL_VERSION}"
            CACHE INTERNAL "Root directory for Lua environment installation."
        )
    endif()

    find_library(
        LUA_LIBRARY
        NAMES lua liblua
        HINTS ${LENV_LUA_ROOT}/lib
        NO_CMAKE_FIND_ROOT_PATH
        NO_DEFAULT_PATH
    )
    find_path(
        LUA_HEADERS_PATH
        lua.h
        HINTS ${LENV_LUA_ROOT}/include
        NO_CMAKE_FIND_ROOT_PATH
        NO_DEFAULT_PATH
    )
    find_program(
        LUA_EXE
        lua
        HINTS ${LENV_LUA_ROOT}/bin
        DOC "The Lua interpreter"
        NO_CMAKE_FIND_ROOT_PATH
        NO_DEFAULT_PATH
    )
    find_program(
        LUAROCKS_EXE
        NAMES luarocks
        HINTS ${LENV_LUA_ROOT}/bin
        DOC "Lua rock installation program"
        NO_CMAKE_FIND_ROOT_PATH
        NO_DEFAULT_PATH
    )
    find_program(
        BUSTED_EXE
        NAMES busted busted.lua
        HINTS ${LENV_LUA_ROOT}/bin
        NAMES_PER_DIR
        DOC "Lua unit testing executable"
        NO_CMAKE_FIND_ROOT_PATH
        NO_DEFAULT_PATH
    )
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
    find_program(
        BUSTED_EXE
        NAMES busted busted.lua
        DOC "Lua unit testing executable"
    )
endif()


if (LUA_HEADERS_PATH STREQUAL "LUA_HEADERS_PATH-NOTFOUND")
    message(FATAL_ERROR "Can't find the Lua header files.")
endif()


find_path(UNICORN_HEADERS_PATH unicorn/unicorn.h)
if (UNICORN_HEADERS_PATH STREQUAL "UNICORN_HEADERS_PATH-NOTFOUND")
    message(FATAL_ERROR "Unicorn doesn't appear to be installed, or the headers are in a non-standard location.")
endif()


execute_process(
    COMMAND ${LUAROCKS_EXE} path --lr-path
    OUTPUT_VARIABLE LUA_CUSTOM_LPATH
    OUTPUT_STRIP_TRAILING_WHITESPACE
)
execute_process(
    COMMAND ${LUAROCKS_EXE} path --lr-cpath
    OUTPUT_VARIABLE LUA_CUSTOM_CPATH
    OUTPUT_STRIP_TRAILING_WHITESPACE
)


# ~~~~~~~~~~~~~~~~~~~~~~~~~~~ Define dependencies ~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

find_library(UNICORN_LIBRARY NAMES unicorn libunicorn)

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Define targets ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

add_subdirectory("src" "${CMAKE_CURRENT_BINARY_DIR}/lib")               # Library code
add_subdirectory("tests/c" "${CMAKE_CURRENT_BINARY_DIR}/tests_c")       # Tests with C++ code
add_subdirectory("tests/lua" "${CMAKE_CURRENT_BINARY_DIR}/test_lua")    # Tests with Lua code
