cmake_minimum_required(VERSION 3.8 FATAL_ERROR)
project(UnicornLua VERSION 0.1 LANGUAGES CXX)

include("${PROJECT_SOURCE_DIR}/configuration.cmake")
include("${PROJECT_SOURCE_DIR}/cmake/install-lua.cmake")
include("${PROJECT_SOURCE_DIR}/cmake/install-luajit.cmake")
include("${PROJECT_SOURCE_DIR}/cmake/install-luarocks.cmake")

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


if(USE_VIRTUALENV)
    if(NOT DEFINED LUA_EXE)
        if(IS_LUAJIT)
            install_luajit()
        else()
            install_lua()
        endif()
    endif()
    install_luarocks()
else()
    find_package(Lua REQUIRED)

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
if(USE_VIRTUALENV)
    set(LUAROCKS_LOCAL_FLAG "")
else()
    set(LUAROCKS_LOCAL_FLAG "--local")
endif()

foreach(_rock IN ITEMS ${REQUIRED_ROCKS})
    if(USE_VIRTUALENV)
        execute_process(
            COMMAND ${LUAROCKS_EXE} install "${_rock}"
            OUTPUT_QUIET
            RESULT_VARIABLE rocks_install_result
        )
    else()
        execute_process(
            COMMAND ${LUAROCKS_EXE} install "--local" "${_rock}"
            OUTPUT_QUIET
            RESULT_VARIABLE rocks_install_result
        )
    endif()

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
