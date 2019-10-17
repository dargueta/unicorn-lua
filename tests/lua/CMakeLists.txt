if ("${LUA_FULL_VERSION}" VERSION_LESS "5.3")
    set(BUSTED_CLI_ARGS --exclude-tags="int64only")
else()
    set(BUSTED_CLI_ARGS "")
endif()

# TODO (dargueta): Try to get the path from the unicornlua_library target instead.
set(BUILT_LIBRARY_DIRECTORY "${CMAKE_BINARY_DIR}/lib")

configure_file(
    "${PROJECT_SOURCE_DIR}/busted-config-template.lua"
    "${CMAKE_CURRENT_BINARY_DIR}/busted-configuration.lua"
)
configure_file(
    "${PROJECT_SOURCE_DIR}/busted-runner-template.sh"
    "${CMAKE_CURRENT_BINARY_DIR}/busted-runner.sh"
)

add_test(
    NAME lua_tests
    COMMAND sh "${CMAKE_CURRENT_BINARY_DIR}/busted-runner.sh"
    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
)
