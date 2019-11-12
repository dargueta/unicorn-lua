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

#if defined(__GNUC__) && defined(__x86__) && defined(USE_FLOAT128)
    #define UCLUA_HAVE_GNUFLOAT128
#endif

#if defined(LDBL_MANT_DIG)
    typedef long double uclua_float80;

    #if LDBL_MANT_DIG == 64
        // `long double` is 80 bits on this platform.
        #define UCLUA_FLOAT80_SIZE 80
    #elif LDBL_MANT_DIG == 113
        // `long double` is 128 bits on this platform.
        #define UCLUA_FLOAT80_SIZE 128
    #else
        // No idea how big a `long double` is but it's biiiig.
        #define UCLUA_FLOAT80_SIZE 0
    #endif
#elif defined(UCLUA_HAVE_GNUFLOAT128)
    // Platform doesn't support `long double` but does support __float128.
    #define UCLUA_FLOAT80_SIZE 128
    typedef __float128 uclua_float80;
#else
    #error "Platform has no way to represent 80-bit floating-point registers."
#endif


enum RegisterDataType {
    UL_REG_TYPE_UNKNOWN,
    UL_REG_TYPE_INT8,           // 1 byte
    UL_REG_TYPE_INT16,          // 2 bytes
    UL_REG_TYPE_INT32,          // 4 bytes
    UL_REG_TYPE_FLOAT32,
    UL_REG_TYPE_INT64,          // 8 bytes
    UL_REG_TYPE_FLOAT64,
    UL_REG_TYPE_INT8_ARRAY_8,
    UL_REG_TYPE_INT16_ARRAY_4,
    UL_REG_TYPE_INT32_ARRAY_2,
    UL_REG_TYPE_INT64_ARRAY_1,
    UL_REG_TYPE_FLOAT80,            // 10 bytes
    UL_REG_TYPE_INT8_ARRAY_16,      // 16 bytes
    UL_REG_TYPE_INT16_ARRAY_8,
    UL_REG_TYPE_INT32_ARRAY_4,
    UL_REG_TYPE_INT64_ARRAY_2,
    UL_REG_TYPE_FLOAT32_ARRAY_4,
    UL_REG_TYPE_FLOAT64_ARRAY_2,
    UL_REG_TYPE_INT8_ARRAY_32,      // 32 bytes
    UL_REG_TYPE_INT16_ARRAY_16,
    UL_REG_TYPE_INT32_ARRAY_8,
    UL_REG_TYPE_INT64_ARRAY_4,
    UL_REG_TYPE_FLOAT32_ARRAY_8,
    UL_REG_TYPE_FLOAT64_ARRAY_4,
    UL_REG_TYPE_INT8_ARRAY_64,      // 64 bytes
    UL_REG_TYPE_INT32_ARRAY_16,
    UL_REG_TYPE_INT64_ARRAY_8,
    UL_REG_TYPE_FLOAT32_ARRAY_16,
    UL_REG_TYPE_FLOAT64_ARRAY_8,
};


class Register {
public:
    Register();
    Register(const void *buffer, RegisterDataType kind);

    void assign_value(const void *buffer, RegisterDataType kind);
    RegisterDataType get_kind() const noexcept;
    size_t get_size() const;
    static size_t size_for_register_kind(RegisterDataType kind);

    int8_t as_int8() const noexcept;
    int16_t as_int16() const noexcept;
    int32_t as_int32() const noexcept;
    int64_t as_int64() const noexcept;

    uclua_float32 as_float32() const noexcept;
    uclua_float64 as_float64() const noexcept;
    uclua_float80 as_float80() const;

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
    std::array<int64_t, 2> as_2xi64() const;

    // AVX
    std::array<uclua_float32, 8> as_8xf32() const;
    std::array<uclua_float64, 4> as_4xf64() const;
    std::array<int8_t, 32> as_32xi8() const;
    std::array<int16_t, 16> as_16xi16() const;
    std::array<int32_t, 8> as_8xi32() const;
    std::array<int64_t, 4> as_4xi64() const;

    // AVX-512
    std::array<uclua_float32, 16> as_16xf32() const;
    std::array<uclua_float64, 8> as_8xf64() const;
    std::array<int8_t, 64> as_64xi8() const;
    std::array<int16_t, 32> as_32xi16() const;
    std::array<int32_t, 16> as_16xi32() const;
    std::array<int64_t, 8> as_8xi64() const;

private:
    template <class T, int N> std::array<T, N> array_cast() const;

    char data_[64];
    RegisterDataType kind_;
};


/**
 * Define a buffer large enough to hold the largest registers available.
 *
 * We need 64 bytes to be able to hold a 512-bit ZMM register. For now, only the
 * low 32 or 64 bits are accessible to Lua. Eventually we'll figure out how to
 * use the rest.
*/
typedef char register_buffer_type[64];


/**
 * Write to an architecture register.
 */
int ul_reg_write(lua_State *L);
int ul_reg_read(lua_State *L);
int ul_reg_write_batch(lua_State *L);
int ul_reg_read_batch(lua_State *L);


/**
 *
 * @warning There's no way to represent a signaling or "indefinite" NaN in C++. Both of
 * these values are returned as std::NAN.
 */
uclua_float80 read_float80(const uint8_t *data);


/**
 *
 * @param value     The floating-point value to store as an 80-bit x86 float.
 * @param buffer    The buffer to store the serialized float into. Must hold at least 10
 *                  bytes.
 *
 * @warning No distinction is made between quiet and signaling NaNs. All NaNs are stored
 * in memory as a quiet NaN.
 */
void write_float80(uclua_float80 value, uint8_t *buffer);

#endif  /* INCLUDE_UNICORNLUA_REGISTERS_H_ */
