function(install_luajit)
    set(LUA_TARBALL "${CMAKE_CURRENT_BINARY_DIR}/lua-${LUA_FULL_VERSION}.tar.gz")
    set(LUA_DOWNLOAD_DIR "${CMAKE_CURRENT_BINARY_DIR}/LuaJIT-${LUAJIT_FULL_VERSION}")
    set(LUA_INSTALL_DIR "${CMAKE_CURRENT_BINARY_DIR}/luajit-install")

    message(STATUS "Downloading and extracting LuaJIT...")
    file(
        DOWNLOAD
        "https://luajit.org/download/LuaJIT-${LUAJIT_FULL_VERSION}.tar.gz"
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

    message(STATUS "Building LuaJIT and installing to: ${LUA_INSTALL_DIR}")
    execute_process(
        COMMAND make -C "${LUA_DOWNLOAD_DIR}" amalg "PREFIX=${LUA_INSTALL_DIR}" "CFLAGS=\"-fPIC\""
        OUTPUT_QUIET
        RESULT_VARIABLE RESULT
    )
    if(NOT RESULT EQUAL 0)
        message(FATAL_ERROR "Failed to build LuaJIT.")
    endif()

    execute_process(
        COMMAND make -C "${LUA_DOWNLOAD_DIR}" "PREFIX=${LUA_INSTALL_DIR}" install
        OUTPUT_QUIET
        RESULT_VARIABLE RESULT
    )
    if(NOT RESULT EQUAL 0)
        message(FATAL_ERROR "Failed to install LuaJIT.")
    endif()

    set(LUA_ROOT "${LUA_INSTALL_DIR}")

    set(LUA_ROOT "${LUA_INSTALL_DIR}" PARENT_SCOPE)
    set(LUA_EXE "${LUA_ROOT}/bin/luajit" PARENT_SCOPE)
    set(LUA_INCLUDE_DIR "${LUA_ROOT}/include/luajit-${LUAJIT_SHORT_VERSION}" PARENT_SCOPE)
    set(LUA_LIBRARY "${LUA_ROOT}/lib/libluajit-${LUA_SHORT_VERSION}.a" PARENT_SCOPE)
endfunction()
