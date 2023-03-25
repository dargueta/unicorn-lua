include_directories(
    "${PROJECT_SOURCE_DIR}/include"
    ${CMAKE_CURRENT_BINARY_DIR}
)

file(GLOB TESTS_CPP_SOURCES "${PROJECT_SOURCE_DIR}/tests/c/*.cpp")

# Pull the doctest.h file we need for unit testing
file(
    DOWNLOAD
    https://raw.githubusercontent.com/onqtam/doctest/master/doctest/doctest.h
    "${CMAKE_CURRENT_BINARY_DIR}/doctest.h"
)

# FIXME (dargueta): Add Lua library as a source
add_executable(
    cpp_test
    ${TESTS_CPP_SOURCES}
    ${CMAKE_CURRENT_BINARY_DIR}/doctest.h
)

if(WIN32)
    target_link_libraries(cpp_test LINK_PUBLIC unicornlua_library)
elseif(UNIX)
    target_link_libraries(
        cpp_test LINK_PUBLIC unicornlua_library ${PTHREADS_LIBRARY}
    )
endif()

add_test(NAME cpp_unit_tests COMMAND cpp_test --order-by=rand)
