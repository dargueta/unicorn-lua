function(install_lua)
    set(LUA_TARBALL "${CMAKE_CURRENT_BINARY_DIR}/lua-${LUA_FULL_VERSION}.tar.gz")
    set(LUA_DOWNLOAD_DIR "${CMAKE_CURRENT_BINARY_DIR}/lua-${LUA_FULL_VERSION}")

    # Vanilla Lua 5.1 has a different local installation root than 5.2+.
    if(LUA_SHORT_VERSION VERSION_EQUAL "5.1")
        set(LUA_ROOT "${LUA_DOWNLOAD_DIR}")
        set(LUA_ROOT "${LUA_DOWNLOAD_DIR}" PARENT_SCOPE)
    else()
        set(LUA_ROOT "${LUA_DOWNLOAD_DIR}/install")
        set(LUA_ROOT "${LUA_DOWNLOAD_DIR}/install" PARENT_SCOPE)
    endif()

    message(STATUS "Downloading and extracting Lua...")
    file(
        DOWNLOAD
        "https://www.lua.org/ftp/lua-${LUA_FULL_VERSION}.tar.gz"
        "${LUA_TARBALL}"
    )

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
    # Before building normal Lua we need to change where it looks for installed
    # libraries. This way we can determine the directory to install the built Unicorn
    # binding with one command, without worrying if we're using a virtual environment
    # or not.
    file(READ "${LUA_DOWNLOAD_DIR}/src/luaconf.h" LUACONF_H_CONTENTS)
    string(
        REGEX REPLACE
        "#define[ \t]+LUA_ROOT[^\n]+\n"
        "#define LUA_ROOT \"${LUA_ROOT}/\"\n"
        MODIFIED_LUACONF_H_CONTENTS
        "${LUACONF_H_CONTENTS}"
    )
    file(WRITE "${LUA_DOWNLOAD_DIR}/src/luaconf.h" "${MODIFIED_LUACONF_H_CONTENTS}")

    # We also need to compile the code as position-independent. On Lua 5.1 the MYCFLAGS
    # variable gets overwritten when compiling for some target platforms, so we can't
    # pass "-fpic" that way. We need to modify the Makefile, similar to how we do above.
    file(READ "${LUA_DOWNLOAD_DIR}/src/Makefile" LUA_SRC_MAKEFILE_CONTENTS)
    string(
        REGEX REPLACE
        "MYCFLAGS=\""
        "MYCFLAGS=\"-fpic "
        MODIFIED_LUA_SRC_MAKEFILE_CONTENTS
        "${LUA_SRC_MAKEFILE_CONTENTS}"
    )
    string(
        REGEX REPLACE
        "MYCFLAGS=-D([^ ]+)"
        "MYCFLAGS=\"-fpic -D\\1\""
        MODIFIED_LUA_SRC_MAKEFILE_CONTENTS
        "${MODIFIED_LUA_SRC_MAKEFILE_CONTENTS}"
    )
    file(WRITE "${LUA_DOWNLOAD_DIR}/src/Makefile" "${MODIFIED_LUA_SRC_MAKEFILE_CONTENTS}")

    # Done configuring Lua -----------------------------------------------------

    message(STATUS "Building Lua and installing to: ${LUA_ROOT}")
    execute_process(
        COMMAND make -C "${LUA_DOWNLOAD_DIR}" "MYCFLAGS=\"-fpic\"" "${DETECTED_LUA_PLATFORM}" local
        OUTPUT_QUIET
        RESULT_VARIABLE RESULT
    )
    if(NOT RESULT EQUAL 0)
        message(FATAL_ERROR "Failed to build Lua.")
    endif()

    if(WIN32)
        # On Windows; PATH has no effect if you're not running in a shell so we need to
        # copy the Lua DLL over to the binary directory so the Lua executable finds it.
        execute_process(
            COMMAND cmake -E copy_if_different ${LUA_ROOT}/lib/lua*.dll ${LUA_ROOT}/bin
            OUTPUT_QUIET
            RESULT_VARIABLE RESULT
        )
        if(NOT RESULT EQUAL 0)
            message(FATAL_ERROR "Failed to copy Lua libraries from ${LUA_ROOT}/lib to ${LUA_ROOT}/bin")
        endif()
    endif()

    set(LUA_EXE "${LUA_ROOT}/bin/lua" PARENT_SCOPE)
    set(LUA_INCLUDE_DIR "${LUA_ROOT}/include" PARENT_SCOPE)
    set(LUA_LIBRARY "${LUA_ROOT}/lib/liblua.a" PARENT_SCOPE)
endfunction()
