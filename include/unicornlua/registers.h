/**
 * Lua bindings for Unicorn register operations.
 *
 * @file registers.h
 */

#pragma once

#include <array>
#include <cfloat>
#include <climits>
#include <cstdint>

#include "unicornlua/lua.h"
#include "unicornlua/register_types.h"

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

class Register {
public:
    Register();
    Register(const void* buffer, RegisterDataType kind);
    static Register from_lua(lua_State* L, int value_index, int kind_index);

    /**
     * Assign a value to this register from memory.
     *
     * @param buffer    The raw data to assign to this register.
     * @param kind      An indication of the type of data this register holds.
     */
    void assign_value(const void* buffer, RegisterDataType kind);

    /**
     * Get the type of the data stored in this register.
     */
    RegisterDataType get_kind() const noexcept;

    /**
     * Get the size of the data in this register, in bytes.
     */
    size_t get_size() const;

    /**
     * Get the size of the given datatype, in bytes.
     */
    static size_t size_for_register_kind(RegisterDataType kind);

    /**
     * Read this register as an 8-bit integer.
     */
    int8_t as_int8() const noexcept;

    /**
     * Read this register as a 16-bit integer.
     */
    int16_t as_int16() const noexcept;

    /**
     * Read this register as a 32-bit integer.
     */
    int32_t as_int32() const noexcept;

    /**
     * Read this register as a 64-bit integer.
     */
    int64_t as_int64() const noexcept;

    /**
     * Read this register as a 32-bit float.
     */
    uclua_float32 as_float32() const noexcept;

    /**
     * Read this register as a 64-bit float.
     */
    uclua_float64 as_float64() const noexcept;

    /**
     * Read this register as an 80-bit float.
     *
     * The bytes in memory are assumed to be in x87 extended-precision format,
     * and are reinterpreted to the host machine's native format.
     */
    uclua_float80 as_float80() const;

    // MMX ---------------------------------------------------------------------

    /**
     * Read this register as an array of eight 8-bit integers.
     */
    std::array<int8_t, 8> as_8xi8() const;

    /**
     * Read this register as an array of four 16-bit integers.
     */
    std::array<int16_t, 4> as_4xi16() const;

    /**
     * Read this register as an array of two 32-bit integers.
     */
    std::array<int32_t, 2> as_2xi32() const;

    /**
     * Read this register as an array of one 64-bit integer.
     *
     * Really this is only provided for symmetry with the other MMX functions
     * that return arrays of integers.
     */
    std::array<int64_t, 1> as_1xi64() const;

    // SSE, SSE2... ------------------------------------------------------------

    /**
     * Read this register as an array of four 32-bit floats.
     *
     * Assumes processor implements SSE.
     */
    std::array<uclua_float32, 4> as_4xf32() const;

    /**
     * Read this register as an array of two 64-bit floats.
     *
     * Assumes processor implements SSE.
     */
    std::array<uclua_float64, 2> as_2xf64() const;

    /**
     * Read this register as an array of sixteen 8-bit integers.
     *
     * Assumes processor implements SSE.
     */
    std::array<int8_t, 16> as_16xi8() const;

    /**
     * Read this register as an array of eight 16-bit integers.
     *
     * Assumes processor implements SSE.
     */
    std::array<int16_t, 8> as_8xi16() const;

    /**
     * Read this register as an array of four 32-bit integers.
     *
     * Assumes processor implements SSE.
     */
    std::array<int32_t, 4> as_4xi32() const;

    /**
     * Read this register as an array of two 64-bit integers.
     *
     * Assumes processor implements SSE.
     */
    std::array<int64_t, 2> as_2xi64() const;

    // AVX ---------------------------------------------------------------------

    /**
     * Read this register as an array of eight 32-bit floats.
     *
     * Assumes processor implements AVX.
     */
    std::array<uclua_float32, 8> as_8xf32() const;

    /**
     * Read this register as an array of four 64-bit floats.
     *
     * Assumes processor implements AVX.
     */
    std::array<uclua_float64, 4> as_4xf64() const;

    /**
     * Read this register as an array of 32 8-bit integers.
     *
     * Assumes processor implements AVX.
     */
    std::array<int8_t, 32> as_32xi8() const;

    /**
     * Read this register as an array of 16 16-bit integers.
     *
     * Assumes processor implements AVX.
     */
    std::array<int16_t, 16> as_16xi16() const;

    /**
     * Read this register as an array of eight 32-bit integers.
     *
     * Assumes processor implements AVX.
     */
    std::array<int32_t, 8> as_8xi32() const;

    /**
     * Read this register as an array of four 64-bit integers.
     *
     * Assumes processor implements AVX.
     */
    std::array<int64_t, 4> as_4xi64() const;

    // AVX-512 -----------------------------------------------------------------

    /**
     * Read this register as an array of sixteen 32-bit floats.
     *
     * Assumes processor implements AVX-512.
     */
    std::array<uclua_float32, 16> as_16xf32() const;

    /**
     * Read this register as an array of eight 64-bit floats.
     *
     * Assumes processor implements AVX-512.
     */
    std::array<uclua_float64, 8> as_8xf64() const;

    /**
     * Read this register as an array of 64 8-bit integers.
     *
     * Assumes processor implements AVX-512.
     */
    std::array<int8_t, 64> as_64xi8() const;

    /**
     * Read this register as an array of 32 16-bit integers.
     *
     * Assumes processor implements AVX-512.
     */
    std::array<int16_t, 32> as_32xi16() const;

    /**
     * Read this register as an array of sixteen 32-bit integers.
     *
     * Assumes processor implements AVX-512.
     */
    std::array<int32_t, 16> as_16xi32() const;

    /**
     * Read this register as an array of eight 64-bit integers.
     *
     * Assumes processor implements AVX-512.
     */
    std::array<int64_t, 8> as_8xi64() const;

    void push_to_lua(lua_State* L) const;

    /**
     * The raw data.
     */
    uint8_t data_[64];

private:
    template <class T, int N>
    std::array<T, N> array_cast() const;

    RegisterDataType kind_;
};

/**
 * Define a buffer large enough to hold the largest registers available.
 *
 * We need 64 bytes to be able to hold a 512-bit ZMM register. For now, only the
 * low 32 or 64 bits are accessible to Lua. Eventually we'll figure out how to
 * use the rest.
 */
typedef uint8_t register_buffer_type[64];

/**
 * Write to an architecture register.
 */
int ul_reg_write(lua_State* L);
int ul_reg_read(lua_State* L);
int ul_reg_write_batch(lua_State* L);
int ul_reg_read_batch(lua_State* L);

/**
 * Read a register from the processor, as something other than as a plain integer.
 *
 * You'll need to use this for reading registers that aren't integers, or for
 * SSE/AVX/AVX-512 registers that can act as arrays of values.
 */
int ul_reg_read_as(lua_State* L);

/**
 * Like @ref ul_reg_read_as, but reads multiple registers at once.
 *
 * The argument to the Lua function is a table mapping the ID of the register to
 * read to the format it should be read in.
 */
int ul_reg_read_batch_as(lua_State* L);

/**
 * Write to a processor register as something other than as a plain integer.
 *
 * You'll need to use this for writing registers that aren't integers, or for
 * SSE/AVX/AVX-512 registers that can act as arrays of values.
 */
int ul_reg_write_as(lua_State* L);

/**
 * Read an x87 floating-point number as the host machine's native format.
 *
 * @warning There's no way to represent a signaling or "indefinite" NaN in C++.
 * Both of these values are returned as std::NAN.
 */
lua_Number read_float80(const uint8_t* data);

/**
 * Store a floating-point value into an x87 floating-point number.
 *
 * @param value     The floating-point value to store as an 80-bit x86 float.
 * @param buffer    The buffer to store the serialized float into. Must hold at
 *                  least 10 bytes.
 *
 * @warning No distinction is made between quiet and signaling NaNs. All NaNs are
 *          stored in memory as a quiet NaN.
 */
void write_float80(lua_Number value, uint8_t* buffer);
