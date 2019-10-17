include_directories(
    "${PROJECT_SOURCE_DIR}/include"
    ${UNICORN_HEADERS_PATH}
    ${LUA_HEADERS_PATH}
    ${CMAKE_CURRENT_BINARY_DIR}
)

file(GLOB TESTS_CPP_SOURCES "${PROJECT_SOURCE_DIR}/tests/c/*.cpp")

# Pull the doctest.h file we need for unit testing
file(
    DOWNLOAD
    https://raw.githubusercontent.com/onqtam/doctest/master/doctest/doctest.h
    "${CMAKE_CURRENT_BINARY_DIR}/doctest.h"
)

add_executable(
    cpp_test
    ${TESTS_CPP_SOURCES}
    ${CMAKE_CURRENT_BINARY_DIR}/doctest.h
)

target_link_libraries(
    cpp_test LINK_PUBLIC unicornlua_library ${UNICORN_LIBRARY} ${PTHREADS_LIBRARY} ${LUA_LIBRARY}
)

add_test(NAME cpp_unit_tests COMMAND cpp_test)
