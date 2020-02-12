#include <array>
#include <cerrno>
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


TEST_CASE("Register::as_int8()") {
    Register reg("\xb6", UL_REG_TYPE_INT8);
    CHECK_EQ(reg.as_int8(), -74);
}


TEST_CASE("Register::as_int16(): 0x7FB6 == 32694") {
    Register reg("\xb6\x7f", UL_REG_TYPE_INT16);
    CHECK_EQ(reg.as_int16(), 0x7fb6);
}


TEST_CASE("Register::as_int16(): 0x8ED1 == -28975") {
    Register reg("\xd1\x8e", UL_REG_TYPE_INT16);
    CHECK_EQ(reg.as_int16(), -28975);
}


TEST_CASE("Register::as_int32(): 0x19E07F88 == 434143112") {
    Register reg("\x88\x7f\xe0\x19", UL_REG_TYPE_INT32);
    CHECK_EQ(reg.as_int32(), 434143112);
}


TEST_CASE("Register::as_int32(): 0xF9E07F88 == -102727800") {
    Register reg("\x88\x7f\xe0\xf9", UL_REG_TYPE_INT32);
    CHECK_EQ(reg.as_int32(), -102727800);
}


TEST_CASE("Register::as_int64(): 0x0000DEADCAFEBEEF == 244838016401135") {
    Register reg("\xef\xbe\xfe\xca\xad\xde\x00\x00", UL_REG_TYPE_INT64);
    CHECK_EQ(reg.as_int64(), 244838016401135);
}


TEST_CASE("Register::as_int64(): 0xCAFEBEEF00000000 == -3819405500257140736") {
    Register reg("\x00\x00\x00\x00\xef\xbe\xfe\xca", UL_REG_TYPE_INT64);
    CHECK_EQ(reg.as_int64(), -3819405500257140736);
}


TEST_CASE("Register::as_float32(): 3.141592654") {
    uclua_float32 value = 3.141592654;
    Register reg((const char *)&value, UL_REG_TYPE_FLOAT32);
    CHECK_EQ(reg.as_float32(), doctest::Approx(value));
}


TEST_CASE("Register::as_float64(): 1.4142135623730951") {
    uclua_float64 value = 1.4142135623730951;
    Register reg((const char *)&value, UL_REG_TYPE_FLOAT64);
    CHECK_EQ(reg.as_float64(), doctest::Approx(value));
}


// TODO (dargueta): Figure out what's broken
#if 0
TEST_CASE("Register::as_float80(): 2.71828182845904524") {
    uint8_t value[10];
    write_float80(2.71828182845904524, value);

    Register reg(value, UL_REG_TYPE_FLOAT80);
    CHECK_EQ(reg.as_float80(), doctest::Approx(2.71828182845904524));
}
#endif


TEST_CASE("Register::as_8xi8()") {
    std::array<int8_t, 8> expected{0x0a, 0x1b, 0x2c, 0x3d, 0x4e, 0x5f, 0x6a, 0x7b};
    Register reg(expected.data(), UL_REG_TYPE_INT8_ARRAY_8);

    CHECK_EQ(reg.as_8xi8(), expected);
}


TEST_CASE("Register::as_4xi16()") {
    std::array<int16_t, 4> expected{0x0a1b, 0x2c3d, 0x4e5f, 0x6a7b};
    Register reg(expected.data(), UL_REG_TYPE_INT16_ARRAY_4);

    CHECK_EQ(reg.as_4xi16(), expected);
}


TEST_CASE("Register::as_2xi32()") {
    std::array<int32_t, 2> expected{-65536, 0x1234abcd};
    Register reg(expected.data(), UL_REG_TYPE_INT32_ARRAY_2);

    CHECK_EQ(reg.as_2xi32(), expected);
}


TEST_CASE("Register::as_1xi64()") {
    std::array<int64_t, 1> expected{-0x655361234abcd};
    Register reg(expected.data(), UL_REG_TYPE_INT32_ARRAY_2);

    CHECK_EQ(reg.as_1xi64(), expected);
}


TEST_CASE("Register::as_8xi16()") {
    std::array<int16_t, 8> expected{32767, -9, 1234, 12345, -18438, 0, 85, 913};
    Register reg(expected.data(), UL_REG_TYPE_INT16_ARRAY_8);

    CHECK_EQ(reg.as_8xi16(), expected);
}


/*

UL_REG_TYPE_INT32_ARRAY_4
UL_REG_TYPE_INT64_ARRAY_2
UL_REG_TYPE_FLOAT32_ARRAY_4
UL_REG_TYPE_FLOAT64_ARRAY_2
UL_REG_TYPE_INT8_ARRAY_32
UL_REG_TYPE_INT16_ARRAY_16
UL_REG_TYPE_INT32_ARRAY_8
UL_REG_TYPE_INT64_ARRAY_4
UL_REG_TYPE_FLOAT32_ARRAY_8
UL_REG_TYPE_FLOAT64_ARRAY_4
UL_REG_TYPE_INT8_ARRAY_64
UL_REG_TYPE_INT32_ARRAY_16
UL_REG_TYPE_INT64_ARRAY_8
UL_REG_TYPE_FLOAT32_ARRAY_16
UL_REG_TYPE_FLOAT64_ARRAY_8
*/
