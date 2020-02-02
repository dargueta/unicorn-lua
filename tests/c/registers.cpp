#include "doctest.h"
#include "fixtures.h"
#include "unicornlua/registers.h"


TEST_CASE("Testing reading float80 -- all zeros = 0") {
    CHECK_MESSAGE(
        read_float80("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00") == 0,
        "All nulls should return 0."
    );
}
