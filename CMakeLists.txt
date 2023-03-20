cmake_minimum_required(VERSION 3.13 FATAL_ERROR)
project(UnicornLua VERSION 2.0.0 LANGUAGES CXX)

include("${PROJECT_SOURCE_DIR}/lua-profile.cmake")

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)


get_filename_component(LUAROCKS_BIN_DIR "${LUAROCKS}" DIRECTORY)
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

set(LUA_LIBRARY "${LUA_LIBDIR}/${LUALIB}")

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Define targets ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #
enable_testing()
# Library code
add_subdirectory("src" "${CMAKE_CURRENT_BINARY_DIR}/lib")
# Tests with C++ code
add_subdirectory("tests/c" "${CMAKE_CURRENT_BINARY_DIR}/tests_c" EXCLUDE_FROM_ALL)
# Tests with Lua code
add_subdirectory("tests/lua" "${CMAKE_CURRENT_BINARY_DIR}/tests_lua" EXCLUDE_FROM_ALL)

configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/templates/Makefile.in"
    "${CMAKE_CURRENT_BINARY_DIR}/Makefile.in"
    @ONLY
)
file(GENERATE
     OUTPUT "${PROJECT_SOURCE_DIR}/Makefile.in"
     INPUT "${CMAKE_CURRENT_BINARY_DIR}/Makefile.in"
)

configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/templates/platform.h"
    "${PROJECT_SOURCE_DIR}/include/unicornlua/platform.h"
    @ONLY
)


find_package(Doxygen QUIET MODULE)
if(DOXYGEN_FOUND)
    option(BUILD_DOCS "Build documentation" ON)

    configure_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/templates/Doxyfile.in"
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
    message(VERBOSE "Doxygen needs to be installed to generate the documentation.")
endif()
