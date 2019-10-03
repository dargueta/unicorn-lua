cmake_minimum_required(VERSION 3.8 FATAL_ERROR)
project("unicorn_lua" VERSION 0.1 LANGUAGES CXX)

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
message(STATUS "Found Luarocks C installation directories: ${LUA_CUSTOM_CPATH}")
execute_process(
    COMMAND ${LUA_EXE} -e "print(string.match('${LUA_CUSTOM_CPATH}', '^([^?]+)'))"
    OUTPUT_VARIABLE LUA_INSTALL_DIR
    OUTPUT_STRIP_TRAILING_WHITESPACE
)


if (${LUA_FULL_VERSION} VERSION_LESS "5.3")
    set(BUSTED_CLI_ARGS --exclude-tags="int64only")
else()
    set(BUSTED_CLI_ARGS "")
endif()


include_directories(
    "include"
    ${UNICORN_HEADERS_PATH}
    ${LUA_HEADERS_PATH}
    ${CMAKE_CURRENT_BINARY_DIR}
)

file(GLOB LIBRARY_CPP_SOURCES "src/*.cpp")
file(GLOB TESTS_CPP_SOURCES "tests/c/*.cpp")

list(
    TRANSFORM ARCHITECTURE_SLUGS
    PREPEND "${CMAKE_CURRENT_BINARY_DIR}/"
    OUTPUT_VARIABLE _arch_files
)
list(TRANSFORM _arch_files APPEND ".cpp")

add_library(
    unicornlua SHARED ${LIBRARY_CPP_SOURCES} ${_arch_files}
)
set_target_properties(
    unicornlua PROPERTIES
    PREFIX ""
    OUTPUT_NAME "unicorn"
)

add_executable(
    cpp_test
    ${TESTS_CPP_SOURCES}
    ${CMAKE_CURRENT_BINARY_DIR}/doctest.h
)


# Apparently OSX requires this stuff: https://stackoverflow.com/q/42371892
if (CMAKE_HOST_APPLE)
    target_link_options(unicornlua BEFORE PUBLIC -dynamiclib -undefined dynamic_lookup)
endif()

target_link_libraries(unicornlua LINK_PUBLIC ${UNICORN_LIBRARY} ${PTHREADS_LIBRARY} ${LUA_LIBRARY})
target_link_libraries(cpp_test LINK_PUBLIC unicornlua ${UNICORN_LIBRARY} ${PTHREADS_LIBRARY} ${LUA_LIBRARY})

if (CMAKE_CXX_COMPILER_ID MATCHES "GNU|AppleClang|Clang")
    add_compile_options(-Wall -Wextra -Werror -Wpedantic)
    if (CMAKE_BUILD_TYPE STREQUAL "Release")
        add_compile_options(-Ofast -fno-rtti)
    else()
        add_compile_options(-O0 -ggdb -frtti)
    endif()
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
    # Visual studio options
    message(FATAL_ERROR "Visual studio not supported yet.")
endif()


# Create commands for autogenerating all the constants files.
foreach(ARCH IN ITEMS ${ARCHITECTURE_SLUGS})
    add_custom_command(
        OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/${ARCH}.cpp"
        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tools/generate_constants.py" "${UNICORN_HEADERS_PATH}/unicorn/${ARCH}.h" "${CMAKE_CURRENT_BINARY_DIR}/${ARCH}.cpp"
    )
endforeach()


# Pull the doctest.h file we need for unit testing
add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/doctest.h
    COMMAND curl -fGs -o ${CMAKE_CURRENT_BINARY_DIR}/doctest.h https://raw.githubusercontent.com/onqtam/doctest/master/doctest/doctest.h
)

configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/busted-config-template.lua"
    "${CMAKE_CURRENT_BINARY_DIR}/.busted"
)
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/busted-runner-template.sh"
    "${CMAKE_CURRENT_BINARY_DIR}/busted-runner.sh"
)


enable_testing()
add_test(NAME cpp_unit_tests COMMAND cpp_test)
add_test(
    NAME lua_tests
    COMMAND sh "${CMAKE_CURRENT_BINARY_DIR}/busted-runner.sh"
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)


install(
    TARGETS unicornlua
    LIBRARY
    DESTINATION ${LUA_INSTALL_DIR}
)
