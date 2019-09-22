/**
 * Lua bindings for Unicorn register operations.
 *
 * @file registers.h
 */

#ifndef INCLUDE_UNICORNLUA_REGISTERS_H_
#define INCLUDE_UNICORNLUA_REGISTERS_H_

#include <array>
#include <cfloat>
#include <climits>
#include <cstdint>

#include "unicornlua/lua.h"


#if FLT_RADIX != 2
    #error "Can't handle floating-point radixes other than 2 right now."
#endif


/**
 *
 * @tparam N    The number of bytes in this emulated floating-point number.
 */
class SoftFloat80;
class SoftFloat128;


#if FLT_MANT_DIG == 24
    typedef float uclua_float32;
#else
    #error "`float` isn't 32 bits. This library can't handle that yet."
#endif

#if DBL_MANT_DIG == 53
    typedef double uclua_float64;
#else
    #error "`double` isn't 64 bits. This library can't handle that yet."
#endif

#if defined(__GNUC__) && defined(__x86_64__) && defined(USE_FLOAT128)
    #define UCLUA_HAVE_GNUFLOAT128
#endif


#ifdef LDBL_MANT_DIG
    #define UCLUA_HAVE_LONG_DOUBLE
    #if LDBL_MANT_DIG == 64
        // `long double` is 80 bits on this platform.
        typedef long double uclua_float80;

        // We have no standard way of representing 128-bit floats. GNU C++ provides the
        // "__float128" type *if* it's enabled on the command line and the target machine
        // supports it. According to the GCC docs, if the target architecture is x86-64
        // then __float128 is IEEE-754 binary128 format and we can use it.
        #if UCLUA_HAVE_GNUFLOAT128
            #define UCLUA_BIG_FLOAT_SIZE 128
            typedef __float128 uclua_float128;
            typedef __float128 uclua_big_float;
        #else
            #define UCLUA_BIG_FLOAT_SIZE 80
            typedef SoftFloat128 uclua_float128;
            typedef long double uclua_big_float;
        #endif
    #elif LDBL_MANT_DIG == 113
        // `long double` is 128 bits on this platform. We need to emulate 80.
        #define UCLUA_BIG_FLOAT_SIZE 128

        typedef SoftFloat80 uclua_float80;
        typedef long double uclua_float128;
        typedef long double uclua_big_float;
    #endif
#else
    // Platform doesn't support `long double` at all.
    typedef SoftFloat80 uclua_float80;

    #ifdef UCLUA_HAVE_GNUFLOAT128
        #define UCLUA_BIG_FLOAT_SIZE 128
        typedef __float128 uclua_float128;
        typedef __float128 uclua_big_float;
    #else
        // No 128-bit floating-point support so we're stuck with `double`
        #define UCLUA_BIG_FLOAT_SIZE 64
        typedef double uclua_big_float;
        typedef SoftFloat128 uclua_float128;
    #endif
#endif

enum RegisterDataType {
    UL_REG_TYPE_UNKNOWN,
    UL_REG_TYPE_INT8,
    UL_REG_TYPE_INT16,
    UL_REG_TYPE_INT32,
    UL_REG_TYPE_INT64,
    UL_REG_TYPE_FLOAT32,
    UL_REG_TYPE_FLOAT64,
    UL_REG_TYPE_FLOAT80,
    UL_REG_TYPE_FLOAT128,

    // SIMD data types

    UL_REG_TYPE_INT8_ARRAY_8,
    UL_REG_TYPE_INT8_ARRAY_16,
    // No int8[32] to my knowledge
    UL_REG_TYPE_INT8_ARRAY_64,
    UL_REG_TYPE_INT16_ARRAY_4,
    UL_REG_TYPE_INT16_ARRAY_8,
    // No int16[16]?
    UL_REG_TYPE_INT32_ARRAY_2,
    UL_REG_TYPE_INT32_ARRAY_4,
    // No int32[8]?
    UL_REG_TYPE_INT32_ARRAY_16,
    UL_REG_TYPE_INT64_ARRAY_1,
    // No int64[2] or int64[4]?
    UL_REG_TYPE_INT64_ARRAY_8,
};


class Register {
    Register();

    void assign_value(const void *buffer, unsigned n_bytes);

    int8_t as_int8() const noexcept;
    int16_t as_int16() const noexcept;
    int32_t as_int32() const noexcept;
    int64_t as_int64() const noexcept;

    uclua_float32 as_float32() const noexcept;
    uclua_float64 as_float64() const noexcept;
    uclua_float80 as_float80() const;
    uclua_float128 as_float128() const;

    // MMX
    std::array<int8_t, 8> as_8xi8() const;
    std::array<int16_t, 4> as_4xi16() const;
    std::array<int32_t, 2> as_2xi32() const;
    std::array<int64_t, 1> as_1xi64() const;

    // SSE, SSE2, etc.
    std::array<uclua_float32, 4> as_4xf32() const;
    std::array<uclua_float64, 2> as_2xf64() const;
    std::array<int8_t, 16> as_16xi8() const;
    std::array<int16_t, 8> as_8xi16() const;
    std::array<int32_t, 4> as_4xi32() const;

    // AVX
    std::array<uclua_float32, 8> as_8xf32() const;
    std::array<uclua_float64, 4> as_4xf64() const;

    // AVX-512
    std::array<int8_t, 64> as_64xi8() const;
    std::array<int16_t, 32> as_32xi16() const;
    std::array<int32_t, 16> as_16xi32() const;
    std::array<int64_t, 8> as_8xi64() const;
    std::array<uclua_float64, 8> as_8xf64() const;
    std::array<uclua_float32, 16> as_16xf32() const;

private:
    template <class T, int N> std::array<T, N> array_cast() const;

    char data_[64];
};


/**
 * Write to an architecture register.
 */
int ul_reg_write(lua_State *L);
int ul_reg_read(lua_State *L);
int ul_reg_write_batch(lua_State *L);
int ul_reg_read_batch(lua_State *L);

#endif  /* INCLUDE_UNICORNLUA_REGISTERS_H_ */
