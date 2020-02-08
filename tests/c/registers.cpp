#include <cmath>
#include <cstring>

#include "doctest.h"
#include "fixtures.h"
#include "unicornlua/registers.h"


TEST_CASE("read_float80(): all zeros = 0") {
    const uint8_t data[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

    uclua_float80 result = read_float80(data);
    CHECK(errno == 0);
    CHECK(result == 0.0);
}


TEST_CASE("read_float80(): fp indefinite, sign = 0") {
    const uint8_t data[] = {0, 0, 0, 0, 0, 0, 0, 0xc0, 0xff, 0x7f};

    uclua_float80 result = read_float80(data);
    CHECK(errno == 0);
    CHECK(std::isnan(result));
}


TEST_CASE("read_float80(): fp indefinite, sign = 1") {
    const uint8_t data[] = {0, 0, 0, 0, 0, 0, 0, 0xc0, 0xff, 0xff};

    uclua_float80 result = read_float80(data);
    CHECK(errno == 0);
    CHECK(std::isnan(result));
}


TEST_CASE("read_float80(): +INF") {
    const uint8_t data[] = {0, 0, 0, 0, 0, 0, 0, 0x80, 0xff, 0x7f};

    uclua_float80 result = read_float80(data);
    CHECK(errno == 0);
    CHECK(std::isinf(result));
    CHECK(std::signbit(result) == false);
}


TEST_CASE("read_float80(): -INF") {
    const uint8_t data[] = {0, 0, 0, 0, 0, 0, 0, 0x80, 0xff, 0xff};

    uclua_float80 result = read_float80(data);
    CHECK(errno == 0);
    CHECK(std::isinf(result));
    CHECK(std::signbit(result) == true);
}


TEST_CASE("read_float80(): qNaN, sign = 0") {
    const uint8_t data[] = {0, 0, 0, 0, 0, 0, 0, 0xc0, 0xff, 0x7f};

    uclua_float80 result = read_float80(data);
    CHECK(errno == 0);
    CHECK(std::isnan(result));
}


TEST_CASE("read_float80(): qNaN, sign = 1") {
    const uint8_t data[] = {0, 0, 0, 0, 0, 0, 0, 0xc0, 0xff, 0xff};

    uclua_float80 result = read_float80(data);
    CHECK(errno == 0);
    CHECK(std::isnan(result));
}


TEST_CASE("read_float80(): 7FFF4000000000000000 = NaN (invalid 80387+)") {
    const uint8_t data[] = {0, 0, 0, 0, 0, 0, 0, 0x40, 0xff, 0x7f};
    uclua_float80 result = read_float80(data);
    CHECK_MESSAGE(errno == EINVAL, "errno should be EINVAL");
    CHECK(std::isnan(result));
}


TEST_CASE("read_float80(): 7FFF8BADC0FFEE15DEAD = sNaN") {
    const uint8_t data[] = {0xad, 0xde, 0x15, 0xee, 0xff, 0xc0, 0xad, 0x8b, 0xff, 0x7f};
    uclua_float80 result = read_float80(data);
    CHECK_MESSAGE(errno == EDOM, "errno should be EDOM");
    CHECK(std::isnan(result));
}


TEST_CASE("read_float80(): 3FFF8000000000000001 == 1.0") {
    int exponent;
    const uint8_t data[] = {1, 0, 0, 0, 0, 0, 0, 0x80, 0xff, 0x3f};

    uclua_float80 result = read_float80(data);
    CHECK(errno == 0);

    uclua_float80 float_significand = frexp(result, &exponent);
    CHECK(exponent == 1);
    CHECK(float_significand == 0.5);
    CHECK(result == 1.0);
}


TEST_CASE("read_float80(): 3FFE8000000000000001 == 0.5") {
    int exponent;
    const uint8_t data[] = {1, 0, 0, 0, 0, 0, 0, 0x80, 0xfe, 0x3f};

    uclua_float80 result = read_float80(data);
    CHECK(errno == 0);

    uclua_float80 float_significand = frexp(result, &exponent);
    CHECK(exponent == 0);
    CHECK(float_significand == 0.5);
    CHECK(result == 0.5);
}


TEST_CASE("read_float80(): 3FFE8000000000000100 == 1.0") {
    int exponent;
    const uint8_t data[] = {4, 0, 0, 0, 0, 0, 0, 0x80, 0xfe, 0x3f};

    uclua_float80 result = read_float80(data);
    CHECK(errno == 0);

    uclua_float80 float_significand = frexp(result, &exponent);
    CHECK(exponent == 2);
    CHECK(float_significand == 0.5);
    CHECK(result == 2.0);
}


// TODO (dargueta): Figure out what's broken
#if 0
TEST_CASE("read_float80(): 4000C90FDAA2922A8000 == 3.141592654") {
    int exponent;
    const uint8_t data[] = {0, 0x80, 0x2a, 0x92, 0xa2, 0xda, 0x0f, 0xc9, 0, 0x40};

    uclua_float80 result = read_float80(data);
    CHECK(errno == 0);

    uclua_float80 float_significand = frexp(result, &exponent);
    CHECK(exponent == 2);
    CHECK(float_significand == 0.7853981635);
    CHECK(result == 3.141592654);
}


TEST_CASE("read_float80(): C000C90FDAA2922A8000 == -3.141592654") {
    int exponent;
    const uint8_t data[] = {0, 0x80, 0x2a, 0x92, 0xa2, 0xda, 0x0f, 0xc9, 0, 0xc0};

    uclua_float80 result = read_float80(data);
    CHECK(errno == 0);

    uclua_float80 float_significand = frexp(result, &exponent);
    CHECK(exponent == 2);
    CHECK(float_significand == -0.7853981635);
    CHECK(result == -3.141592654);
}
#endif


TEST_CASE("write_float80(): 0 -> 00000000000000000000") {
    const uint8_t expected[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    uint8_t result[10];

    write_float80(0, result);
    CHECK(memcmp(expected, result, 10) == 0);
}


TEST_CASE("write_float80(): NaN -> FFFFFFFFFFFFFFFFFFFF") {
    const uint8_t expected[] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
    };
    uint8_t result[10];

    write_float80(NAN, result);
    CHECK(memcmp(expected, result, 10) == 0);
}


TEST_CASE("write_float80(): +INF -> 7FFF8000000000000000") {
    const uint8_t expected[] = {0, 0, 0, 0, 0, 0, 0, 0x80, 0xff, 0x7f};
    uint8_t result[10];

    write_float80(INFINITY, result);
    CHECK(memcmp(expected, result, 10) == 0);
}


TEST_CASE("write_float80(): -INF -> FFFF8000000000000000") {
    const uint8_t expected[] = {0, 0, 0, 0, 0, 0, 0, 0x80, 0xff, 0xff};
    uint8_t result[10];

    write_float80(-INFINITY, result);
    CHECK(memcmp(expected, result, 10) == 0);
}


// TODO (dargueta): Figure out what's broken
#if 0
TEST_CASE("write_float80(): 3.141592654 -> 4000C90FDAA2922A8000") {
    const uint8_t expected[] = {
        0, 0x80, 0x2a, 0x92, 0xa2, 0xda, 0x0f, 0xc9, 0, 0xc0
    };
    uint8_t result[10];

    write_float80(3.141592654, result);
    CHECK(memcmp(expected, result, 10) == 0);
}
#endif
