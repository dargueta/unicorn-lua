# Variables needed
#
#   [x] LIB_EXTENSION
#   [ ] LIBDIR
#   [x] LUA
#   [x] LUA_INCDIR
#   [x] LUA_LIBDIR
#   [ ] PREFIX
#   [x] PTHREAD_LIBDIR
#   [x] UNICORN_INCDIR
#   [x] UNICORN_LIBDIR

if(NOT DEFINED LUA)
    find_program(
        LUA lua
        HINTS "${PROJECT_SOURCE_DIR}/.venv"
              "${CMAKE_CURRENT_SOURCE_DIR}/.venv"
              "${CMAKE_HOME_DIRECTORY}/.lua"
              "${LUA_BINDIR}"
        REQUIRED
    )
endif()


if(NOT DEFINED LUA_BINDIR)
    cmake_path(GET LUA PARENT_PATH LUA_BINDIR)
endif()


if(NOT DEFINED LUA_VERSION)
    execute_process(
        COMMAND $(LUA) -e "v = _VERSION:gsub('^Lua (%d+%.%d+)$', '%1') print(v)"
        OUTPUT_VARIABLE LUA_VERSION
    )
endif()


string(REPLACE "." "" LUA_VERSION_NO_DOT "${LUA_VERSION}")

if(NOT DEFINED UNICORN_LIBDIR)
    find_library(
        UNICORN_LIBRARY
        NAMES unicorn libunicorn
        PATHS /usr/lib64 /usr/lib32 /usr/libx32
        REQUIRED
    )
    cmake_path(GET UNICORN_LIBRARY PARENT_PATH UNICORN_LIBDIR)
endif()


if(NOT DEFINED PTHREAD_LIBDIR)
    # pthread is only needed on *NIX systems
    if(WIN32)
        set(PTHREAD_LIBDIR "")
    else()
        find_library(PTHREAD_LIBRARY NAMES pthread libpthread REQUIRED)
        cmake_path(GET PTHREAD_LIBRARY PARENT_PATH PTHREAD_LIBDIR)
    endif()
endif()


if(NOT DEFINED LIB_EXTENSION)
    if(WIN32)
        set(LIB_EXTENSION "dll")
    else()
        set(LIB_EXTENSION "so")
    endif()
endif()


if(NOT DEFINED UNICORN_INCDIR)
    find_path(UNICORN_INCDIR NAMES unicorn/unicorn.h REQUIRED)
endif()


if(NOT DEFINED LUA_INCDIR OR "${LUA_INCDIR}" STREQUAL "")
    find_path(
        LUA_INCDIR
        NAMES lauxlib.h
        PATHS ".venv/include" "${CMAKE_HOME_DIRECTORY}/.lua/include"
        REQUIRED
    )
endif()


if(NOT DEFINED LUA_LIBDIR OR "${LUA_LIBDIR}" STREQUAL "")
    if(UNIX)
        cmake_path(GET LUA_INCDIR PARENT_PATH LUA_DIR)
        cmake_path(APPEND LUA_DIR "lib" OUTPUT_VARIABLE LUA_LIBDIR)
    else()
        # Windows
        find_library(
            LUA_LIBRARY
            NAMES lua.lib "lua${LUA_VERSION_NO_DOT}.lib"
            PATHS "${LUA_BINDIR}/../lib"
            REQUIRED
        )

        cmake_path(GET LUA_LIBRARY PARENT_PATH LUA_LIBDIR)
        if(NOT DEFINED LUA_LIBDIR_FILE)
            cmake_path(GET LUA_LIBRARY FILENAME LUA_LIBDIR_FILE)
        endif()
    endif()
endif()


if(NOT DEFINED LUA_LIBDIR_FILE OR LUA_LIBDIR_FILE STREQUAL "")
    # LUA_LIBDIR is guaranteed to be defined in here. LUA_LIBRARY may or may not
    # depending on if we had to find it ourselves earlier.
    if(UNIX AND NOT DEFINED LUA_LIBRARY)
        find_file(
            LUA_LIBRARY
            NAMES liblua.a "liblua${LUA_VERSION}.a" "liblua${LUA_VERSION_NO_DOT}.a"
            PATHS "${LUA_LIBDIR}"
            REQUIRED
            NO_CMAKE_PATH
        )
    elseif(NOT DEFINED LUA_LIBRARY)
        # We're on Windows (probably) and LUA_LIBRARY wasn't defined earlier.
        find_file(
            LUA_LIBRARY
            NAMES lua.lib "lua${LUA_VERSION_NO_DOT}.lib"
            PATHS "${LUA_LIBDIR}"
            REQUIRED
            NO_CMAKE_PATH
        )
    endif()
    cmake_path(GET LUA_LIBRARY FILENAME LUA_LIBDIR_FILE)
endif()
