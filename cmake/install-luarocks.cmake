function(install_luarocks)
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
                   "--with-lua-include=${LUA_INCLUDE_DIR}"
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
        message(FATAL_ERROR "Failed to install LuaRocks.")
    endif()

    set(LUAROCKS_DOWNLOAD_DIR "${CMAKE_CURRENT_BINARY_DIR}/luarocks-${LUAROCKS_VERSION}")
    set(LUAROCKS_INSTALL_DIR "${LUAROCKS_DOWNLOAD_DIR}-installation")

    set(LUAROCKS_DOWNLOAD_DIR "${CMAKE_CURRENT_BINARY_DIR}/luarocks-${LUAROCKS_VERSION}" PARENT_SCOPE)
    set(LUAROCKS_INSTALL_DIR "${LUAROCKS_DOWNLOAD_DIR}-installation" PARENT_SCOPE)
    set(LUAROCKS_EXE "${LUAROCKS_INSTALL_DIR}/bin/luarocks" PARENT_SCOPE)
endfunction()
