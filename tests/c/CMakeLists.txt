include_directories(
    "${PROJECT_SOURCE_DIR}/include"
    ${UNICORN_HEADERS_PATH}
    ${LUA_INCDIR}
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

if(IS_LUAJIT)
    target_compile_definitions(cpp_test PUBLIC IS_LUAJIT=1)
endif()

if (CMAKE_CXX_COMPILER_ID MATCHES "GNU|AppleClang|Clang")
    target_compile_options(cpp_test PRIVATE -Wall -Wextra -Werror -Wpedantic -frtti)
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
    # Visual studio options
    # We need to predefine the NOMINMAX macro to get around a naming collision
    # in MSVC:
    # https://stackoverflow.com/questions/1394132/macro-and-member-function-conflict
    # https://github.com/microsoft/cppwinrt/issues/479
    target_compile_options(cpp_test PRIVATE /Wall /WX /D NOMINMAX /external:anglebrackets /external:W0)
else()
    message(FATAL_ERROR "Unrecognized compiler: ${CMAKE_CXX_COMPILER_ID}")
endif()

target_link_libraries(
    cpp_test LINK_PUBLIC unicornlua_library ${UNICORN_LIBRARY} ${PTHREADS_LIBRARY} ${LUA_LIBRARY}
)

add_test(NAME cpp_unit_tests COMMAND cpp_test --order-by=rand)
