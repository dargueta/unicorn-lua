include_directories(
    "${PROJECT_SOURCE_DIR}/include"
    ${CMAKE_CURRENT_BINARY_DIR}
)

file(GLOB TESTS_CPP_SOURCES "${PROJECT_SOURCE_DIR}/tests/c/*.cpp")

set(STATIC_LUA_LIBRARY "${LUA_LIBDIR}/${LUA_LIBDIR_FILE}")


# FIXME (dargueta): Add Lua library as a source
add_executable(cpp_test ${TESTS_CPP_SOURCES})

if(WIN32)
    target_link_libraries(cpp_test LINK_PUBLIC unicornlua_library "${STATIC_LUA_LIBRARY}")
elseif(UNIX)
    target_link_libraries(
        cpp_test LINK_PUBLIC unicornlua_library "${PTHREADS_LIBRARY}" "${STATIC_LUA_LIBRARY}"
    )
endif()

add_test(NAME cpp_unit_tests COMMAND cpp_test --order-by=rand)
