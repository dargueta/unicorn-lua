cmake_minimum_required(VERSION 3.18 FATAL_ERROR)
project(UnicornLua VERSION 2.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)


get_filename_component(LUAROCKS_BIN_DIR "${LUAROCKS}" DIRECTORY)
set(BUSTED_EXE "${LUAROCKS_BIN_DIR}/busted")

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

if(IS_LUAJIT)
    add_compile_definitions(IS_LUAJIT=1)
endif()


if (CMAKE_CXX_COMPILER_ID MATCHES "GNU|AppleClang|Clang")
    add_compile_options(-Wall -Wextra -Werror -Wpedantic -pedantic-errors)
    set(CMAKE_CXX_FLAGS_DEBUG "-O0 -ggdb -frtti")
    set(CMAKE_CXX_FLAGS_RELEASE "-Ofast -fno-rtti")
elseif(MSVC)
    # Visual studio options
    add_compile_options(/Wall /WX /wd4820 /wd5045 /external:anglebrackets /external:W0)
    set(CMAKE_CXX_FLAGS_DEBUG "/Od /Z7 /GR")
    set(CMAKE_CXX_FLAGS_RELEASE "/Ot /GR-")

    # We need to predefine the NOMINMAX macro to get around a naming collision
    # in MSVC:
    # https://stackoverflow.com/questions/1394132/macro-and-member-function-conflict
    # https://github.com/microsoft/cppwinrt/issues/479
    add_compile_definitions(NOMINMAX)
else()
    message(FATAL_ERROR "Unrecognized compiler: ${CMAKE_CXX_COMPILER_ID}")
endif()


include_directories("${UNICORN_INCDIR}" "${LUA_INCDIR}")
link_directories("${UNICORN_LIBDIR}" "${LUA_LIBDIR}")
link_libraries(unicorn)

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Define targets ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #
enable_testing()
# Library code
add_subdirectory("src" "${CMAKE_CURRENT_BINARY_DIR}/lib")
# Tests with C++ code
add_subdirectory("tests/c" "${CMAKE_CURRENT_BINARY_DIR}/tests_c" EXCLUDE_FROM_ALL)
# Tests with Lua code
add_subdirectory("tests/lua" "${CMAKE_CURRENT_BINARY_DIR}/tests_lua" EXCLUDE_FROM_ALL)


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
