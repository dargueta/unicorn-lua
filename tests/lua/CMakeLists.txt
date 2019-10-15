if ("${LUA_FULL_VERSION}" VERSION_LESS "5.3")
    set(BUSTED_CLI_ARGS --exclude-tags="int64only")
else()
    set(BUSTED_CLI_ARGS "")
endif()


configure_file(
    "${PROJECT_SOURCE_DIR}/busted-config-template.lua"
    "${CMAKE_CURRENT_BINARY_DIR}/busted-configuration.lua"
)
configure_file(
    "${PROJECT_SOURCE_DIR}/busted-runner-template.sh"
    "${CMAKE_CURRENT_BINARY_DIR}/busted-runner.sh"
)


enable_testing()
add_test(
    NAME lua_tests
    COMMAND sh "${CURRENT_BINARY_DIR}/busted-runner.sh"
    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
)
