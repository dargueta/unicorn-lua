cmake_minimum_required(VERSION 3.12 FATAL_ERROR)
project(UnicornLua VERSION 0.1 LANGUAGES CXX)

include("${PROJECT_SOURCE_DIR}/configuration.cmake")

option(BUILD_DOCS "Build documentation" ON)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

#find_package(Python3 REQUIRED)

if(NOT USE_VIRTUALENV)
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

# Lua looks for C libraries with the file extension `.dll` on Windows, and `.so` on all
# other platforms. Since the OSX extension is `.dylib` we can't use CMAKE_SHARED_LIBRARY_SUFFIX
# so we have to override it ourselves.
if(CMAKE_HOST_WIN32)
    set(LUA_CLIB_EXTENSION ".dll")
else()
    set(LUA_CLIB_EXTENSION ".so")
endif()

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Define targets ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #
enable_testing()
add_subdirectory("src" "${CMAKE_CURRENT_BINARY_DIR}/lib")               # Library code
add_subdirectory("tests/c" "${CMAKE_CURRENT_BINARY_DIR}/tests_c")       # Tests with C++ code
add_subdirectory("tests/lua" "${CMAKE_CURRENT_BINARY_DIR}/tests_lua")   # Tests with Lua code

file(GENERATE
    OUTPUT "${PROJECT_SOURCE_DIR}/build-target.in"
    CONTENT "SHARED_LIB_FILE=$<TARGET_FILE:unicornlua_library>\nTEST_EXE_FILE=$<TARGET_FILE:cpp_test>\nBUILT_LIBRARY_DIRECTORY=$<TARGET_FILE_DIR:unicornlua_library>\n"
)
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/makefile-variables.in"
    "${PROJECT_SOURCE_DIR}/Makefile.in"
    @ONLY
)
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/templates/platform.h"
    "${PROJECT_SOURCE_DIR}/include/unicornlua/platform.h"
    @ONLY
)


find_package(Doxygen)
if(DOXYGEN_FOUND)
    configure_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/cmake/Doxyfile.in"
        "${CMAKE_CURRENT_BINARY_DIR}/Doxyfile"
        @ONLY
    )

    add_custom_target(
        docs
        COMMAND ${DOXYGEN_EXECUTABLE}
        WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
        COMMENT "Generating API documentation with Doxygen"
        VERBATIM
    )
else()
  message("Doxygen needs to be installed to generate the documentation.")
endif()
