if ("${LUA_FULL_VERSION}" VERSION_LESS "5.3")
    set(BUSTED_CLI_ARGS --exclude-tags="int64only")
else()
    set(BUSTED_CLI_ARGS "")
endif()

configure_file(
    "${PROJECT_SOURCE_DIR}/templates/busted-config.lua"
    "${CMAKE_CURRENT_BINARY_DIR}/busted-config-temp.lua"
    @ONLY
)
file(GENERATE
    OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/busted-config.lua"
    INPUT "${CMAKE_CURRENT_BINARY_DIR}/busted-config-temp.lua"
)

configure_file(
    "${PROJECT_SOURCE_DIR}/templates/busted-runner.sh"
    "${CMAKE_CURRENT_BINARY_DIR}/busted-runner.sh"
    @ONLY
)

add_test(
    NAME lua_tests
    COMMAND sh "${CMAKE_CURRENT_BINARY_DIR}/busted-runner.sh"
    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
)
