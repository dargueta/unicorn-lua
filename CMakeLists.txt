cmake_minimum_required(VERSION 3.8 FATAL_ERROR)
project(UnicornLua VERSION 0.1 LANGUAGES CXX)

include("${PROJECT_SOURCE_DIR}/configuration.cmake")

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_PLATFORM_INDEPENDENT_CODE ON)

if (NOT DEFINED ARCHITECTURE_SLUGS)
    set(ARCHITECTURE_SLUGS arm;arm64;mips;m68k;sparc;x86)
endif()


# These are the rocks required for running tests and using examples.
set(REQUIRED_ROCKS lcurses;busted)

find_package(Python3 REQUIRED)


function(download_lua)
    set(LUA_TARBALL "${CMAKE_CURRENT_BINARY_DIR}/lua-${LUA_FULL_VERSION}.tar.gz")
    set(LUA_DOWNLOAD_DIR "${CMAKE_CURRENT_BINARY_DIR}/lua-${LUA_FULL_VERSION}")

    # Vanilla Lua 5.1 has a different local installation root than 5.2+.
    if(NOT IS_LUAJIT AND (LUA_SHORT_VERSION VERSION_EQUAL "5.1"))
        set(LUA_ROOT "${LUA_DOWNLOAD_DIR}")
    else()
        set(LUA_ROOT "${LUA_DOWNLOAD_DIR}/install")
    endif()

    message(STATUS "Downloading and extracting Lua...")
    if(IS_LUAJIT)
        file(
            DOWNLOAD
            "https://www.luajit.org/download/LuaJIT-${LUA_FULL_VERSION}.tar.gz"
            "${LUA_TARBALL}"
        )
    else()
        file(
            DOWNLOAD
            "https://www.lua.org/ftp/lua-${LUA_FULL_VERSION}.tar.gz"
            "${LUA_TARBALL}"
        )
    endif()
    execute_process(
        COMMAND cmake -E tar -xz "${LUA_TARBALL}"
        WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
        OUTPUT_QUIET
        RESULT_VARIABLE RESULT
    )
    if(NOT RESULT EQUAL 0)
        message(FATAL_ERROR "Failed to extract Lua tarball.")
    endif()


    message(STATUS "Configuring Lua...")
    if(NOT IS_LUAJIT)
        # Before building normal Lua we need to change where it looks for installed
        # libraries. This way we can determine the directory to install the built Unicorn
        # binding with one command, without worrying if we're using a virtual environment
        # or not.
        file(READ "${LUA_DOWNLOAD_DIR}/src/luaconf.h" LUACONF_H_CONTENTS)
        string(
            REGEX REPLACE
            "#define[ \t]+LUA_ROOT[^\n]+\n" "#define LUA_ROOT \"${LUA_ROOT}/\"\n"
            MODIFIED_LUACONF_H_CONTENTS
            "${LUACONF_H_CONTENTS}"
        )
        file(WRITE "${LUA_DOWNLOAD_DIR}/src/luaconf.h" "${MODIFIED_LUACONF_H_CONTENTS}")
    endif()

    message(STATUS "Building Lua and installing to: ${LUA_ROOT}")
    if(NOT IS_LUAJIT)
        execute_process(
            COMMAND make -C "${LUA_DOWNLOAD_DIR}" "MYCFLAGS=\"-fPIC\"" "${DETECTED_LUA_PLATFORM}" local
            OUTPUT_QUIET
            RESULT_VARIABLE RESULT
        )
        if(NOT RESULT EQUAL 0)
            message(FATAL_ERROR "Failed to build Lua.")
        endif()
    else()
        execute_process(
            COMMAND make -C "${LUA_DOWNLOAD_DIR}" "PREFIX=${LUA_ROOT}" "CFLAGS=\"$ENV{CFLAGS} -fPIC\""
            OUTPUT_QUIET
            RESULT_VARIABLE RESULT
        )
        if(NOT RESULT EQUAL 0)
            message(FATAL_ERROR "Failed to build LuaJIT.")
        endif()

        execute_process(
            COMMAND make -C "${LUA_DOWNLOAD_DIR}" "PREFIX=${LUA_ROOT}" "DESTDIR=${LUA_ROOT}" install
            OUTPUT_QUIET
            RESULT_VARIABLE RESULT
        )
        if(NOT RESULT EQUAL 0)
            message(FATAL_ERROR "Failed to install LuaJIT.")
        endif()
    endif()

    # Install LuaRocks -------------------------------------------------------------

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
        OUTPUT_QUIET
        RESULT_VARIABLE RESULT
    )
    if(NOT RESULT EQUAL 0)
        message(FATAL_ERROR "Failed to extract LuaRocks.")
    endif()

    message(STATUS "Building LuaRocks...")
    execute_process(
        COMMAND sh "${LUAROCKS_DOWNLOAD_DIR}/configure"
                   "--prefix=${LUAROCKS_INSTALL_DIR}"
                   "--with-lua=${LUA_ROOT}"
                   "--force-config"
        WORKING_DIRECTORY "${LUAROCKS_DOWNLOAD_DIR}"
        RESULT_VARIABLE RESULT
    )
    if(NOT RESULT EQUAL 0)
        message(FATAL_ERROR "Failed to build LuaRocks.")
    endif()

    message(STATUS "Installing LuaRocks to: ${LUAROCKS_INSTALL_DIR}")
    execute_process(
        COMMAND make -C "${LUAROCKS_DOWNLOAD_DIR}" bootstrap
        OUTPUT_QUIET
        RESULT_VARIABLE RESULT
    )
    if(NOT RESULT EQUAL 0)
        message(FATAL_ERROR "Failed to install required rocks.")
    endif()
endfunction(download_lua)



if(USE_VIRTUALENV)
    set(LUA_DOWNLOAD_DIR "${CMAKE_CURRENT_BINARY_DIR}/lua-${LUA_FULL_VERSION}")
    set(LUA_ROOT "${LUA_DOWNLOAD_DIR}/install")
    set(LUA_EXE "${LUA_ROOT}/bin/lua")
    set(LUA_HEADERS_PATH "${LUA_ROOT}/include")
    set(LUA_LIBRARY "${LUA_ROOT}/lib/liblua.a")
    set(LUAROCKS_DOWNLOAD_DIR "${CMAKE_CURRENT_BINARY_DIR}/luarocks-${LUAROCKS_VERSION}")
    set(LUAROCKS_INSTALL_DIR "${LUAROCKS_DOWNLOAD_DIR}-installation")
    set(LUAROCKS_EXE "${LUAROCKS_INSTALL_DIR}/bin/luarocks")

    if(NOT EXISTS "${LUA_EXE}")
        download_lua()
    endif()
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
foreach(_rock IN ITEMS ${REQUIRED_ROCKS})
    execute_process(
        COMMAND ${LUAROCKS_EXE} install "${_rock}"
        OUTPUT_QUIET
        RESULT_VARIABLE rocks_install_result
    )
    if(NOT rocks_install_result EQUAL 0)
        message(FATAL_ERROR "Installing rock ${_rock} failed.")
    endif()
endforeach()


get_filename_component(LUAROCKS_BIN_DIR "${LUAROCKS_EXE}" DIRECTORY)
set(BUSTED_EXE "${LUAROCKS_BIN_DIR}/busted")

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~ Define dependencies ~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

# These might be set by the user.
if(NOT DEFINED UNICORN_LIBRARY)
    find_library(UNICORN_LIBRARY NAMES unicorn libunicorn)
endif()

if(NOT DEFINED UNICORN_HEADERS_PATH)
    find_path(UNICORN_HEADERS_PATH unicorn/unicorn.h)
endif()

if (UNICORN_HEADERS_PATH STREQUAL "UNICORN_HEADERS_PATH-NOTFOUND")
    message(FATAL_ERROR "Unicorn doesn't appear to be installed, or the headers are in a non-standard location.")
endif()

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Define targets ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #
enable_testing()
add_subdirectory("src" "${CMAKE_CURRENT_BINARY_DIR}/lib")               # Library code
add_subdirectory("tests/c" "${CMAKE_CURRENT_BINARY_DIR}/tests_c")       # Tests with C++ code
add_subdirectory("tests/lua" "${CMAKE_CURRENT_BINARY_DIR}/tests_lua")   # Tests with Lua code
