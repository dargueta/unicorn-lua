#include <array>
#include <cerrno>
#include <cfenv>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <numeric>
#include <sstream>

#include <unicorn/unicorn.h>
#include <unicorn/x86.h>

#include "unicornlua/compat.h"
#include "unicornlua/engine.h"
#include "unicornlua/errors.h"
#include "unicornlua/lua.h"
#include "unicornlua/registers.h"
#include "unicornlua/utils.h"


const uint8_t kFP80PositiveInfinity[] = {0, 0, 0, 0, 0, 0, 0, 0x80, 0xff, 0x7f};
const uint8_t kFP80NegativeInfinity[] = {0, 0, 0, 0, 0, 0, 0, 0x80, 0xff, 0xff};
const uint8_t kFP80SignalingNaN[] = {1, 0, 0, 0, 0, 0, 0, 0, 0xf0, 0x7f};


lua_Number read_float80(const uint8_t *data) {
    uint64_t significand = *reinterpret_cast<const uint64_t *>(data);
    int exponent = *reinterpret_cast<const uint16_t *>(data + 8) & 0x7fff;
    bool sign = (*reinterpret_cast<const uint16_t *>(data + 8) & 0x8000) != 0;

    // Clear errno before starting because we use it to indicate that the return
    // value is valid on some FPUs but not others, or if the NaN is a signaling
    // one.
    errno = 0;

    if (exponent == 0) {
        if (significand == 0)
            return 0.0;
        if (sign)
            return std::ldexp(-static_cast<double>(significand), -16382);
        return std::ldexp(significand, -16382);
    }
    else if (exponent == 0x7fff) {
        // Top two bits of the significand will tell us what kind of number this
        // is and aren't used for storing a value.
        switch ((significand >> 62) & 3) {
            case 0:
                if (significand == 0)
                    return static_cast<lua_Number>(sign ? -INFINITY : +INFINITY);

                // Significand is non-zero, fall through to next case.
                #ifndef _MSC_VER
                __attribute__ ((fallthrough));
                #endif
            case 1:
                /* 8087 - 80287 treat this as a signaling NaN, 80387 and later
                 * treat this as an invalid operand and will explode. Compromise
                 * by setting errno and returning NaN instead of throwing an
                 * exception.
                 */
                errno = EINVAL;
                return std::numeric_limits<lua_Number>::signaling_NaN();
            case 2:
                if ((significand & 0x3fffffffffffffffULL) == 0)
                    return static_cast<lua_Number>(sign ? -INFINITY : +INFINITY);

                // Else: This is a signaling NaN. We don't want to throw an
                // exception because Lua is just reading the registers of the
                // processor, not using them.
                return std::numeric_limits<lua_Number>::signaling_NaN();
            case 3:
                /* If the significand is 0, this is an indefinite value (result
                 * of 0/0, infinity/infinity, etc.). Otherwise, this is a quiet
                 * NaN. In either case, we return NAN.
                 */
                return NAN;
            default:
                throw std::logic_error(
                    "BUG: Bit masking on bits 63-62 of float80 significand got"
                    " an unexpected value. This should never happen."
                );
        }
    }

    // If the high bit of the significand is set, this is a normal value. Ignore
    // the high bit of the significand and compensate for the exponent bias.
    auto f_part = static_cast<lua_Number>(significand & 0x7fffffffffffffffULL);
    if (sign)
        f_part *= -1;

    if (significand & 0x8000000000000000ULL)
        return std::ldexp(f_part, exponent - 16383);

    // Unnormal number. Invalid on 80387+; 80287 and earlier use a different
    // exponent bias.
    errno = EINVAL;
    return std::ldexp(f_part, exponent - 16382);
}


static bool is_snan(lua_Number value) {
    fenv_t env;

    // Disable floating-point exception traps and clear all exception information.
    // The current state is saved for later.
    std::feholdexcept(&env);
    std::feclearexcept(FE_ALL_EXCEPT);

    // Multiply NaN by 1. If `value` is a signaling NaN this should trigger a
    // floating-point exception.
    value = value * 1;

    // Get the exception state and see if any exceptions were thrown. If so, then
    // `value` was a signaling NaN.
    int fenv_flags = std::fetestexcept(FE_ALL_EXCEPT);

    // Reset the environment to what it was before and check the exception flags
    // for what we were expecting.
    std::fesetenv(&env);
    return (fenv_flags & FE_INVALID) != 0;

}


void write_float80(lua_Number value, uint8_t *buffer) {
    int f_type = std::fpclassify(value);
    uint16_t sign_bit = std::signbit(value) ? 0x8000U : 0U;

    switch (f_type) {
        case FP_INFINITE:
            if (sign_bit)
                memcpy(buffer, kFP80NegativeInfinity, 10);
            else
                memcpy(buffer, kFP80PositiveInfinity, 10);
            return;
        case FP_NAN:
            if (is_snan(value))
                memcpy(buffer, kFP80SignalingNaN, sizeof(kFP80SignalingNaN));
            else
                // All bytes 0xFF is a quiet NaN
                memset(buffer, 0xff, 10);
            return;
        case FP_ZERO:
            memset(buffer, 0, 10);
            return;
        case FP_SUBNORMAL:
        case FP_NORMAL:
            // This is a more complicated case and we handle it farther down.
            break;
        default:
            throw std::runtime_error(
                "Unrecognized value returned from std::fpclassify(). This library was"
                " probably compiled on a newer standard of C++ than it was written for."
                " Please file a bug ticket."
            );
    }

    int exponent;
    uclua_float80 float_significand = std::frexp(value, &exponent);

    if ((exponent <= -16383) || (exponent >= 16384))
        throw std::domain_error(
            "Can't convert value outside representable range for 80-bit float without"
            " loss of precision."
        );

    // The high bit of the significand is always set for normal numbers, and clear for
    // denormal numbers. This means the significand is 63 bits, not 64, hence why we
    // multiply here by 2^62 and not 2^63.
    auto int_significand = static_cast<uint64_t>(
        static_cast<int64_t>(float_significand) * (1ULL << 62)
    );
    if (f_type == FP_NORMAL) {
        int_significand |= 1ULL << 63;
        exponent += 16383;
    }
    else
        exponent = 0;

    *reinterpret_cast<uint64_t *>(buffer) = int_significand;

#ifdef _MSC_VER
// I don't know why MSVC is screaming at me about signed/unsigned mixing
#pragma warning(push)
#pragma warning(disable:4365)
#endif
    *reinterpret_cast<uint16_t *>(buffer + 8U) =
        static_cast<uint16_t>(exponent) | sign_bit;
#ifdef _MSC_VER
#pragma warning(pop)
#endif
}


template <class T, size_t N>
void integer_array_to_table(lua_State *L, const std::array<T, N>& arr) {
    static_assert(N > 0 && N <= 128, "Array length must be in [1, 128]");
    lua_createtable(L, N, 0);

    for (size_t i = 0; i < N; ++i) {
        lua_pushinteger(L, arr[i]);
        lua_seti(L, -2, static_cast<int>(i) + 1);
    }
}


template <class T, size_t N>
void float_array_to_table(lua_State *L, const std::array<T, N>& arr) {
    static_assert(N > 0 && N <= 128, "Array length must be in [1, 128]");
    lua_createtable(L, N, 0);

    for (size_t i = 0; i < N; ++i) {
        lua_pushnumber(L, arr[i]);
        lua_seti(L, -2, static_cast<int>(i) + 1);
    }
}


template <class T, int N>
std::array<T, N> Register::array_cast() const {
    std::array<T, N> value{};
    memcpy(value.data(), data_, sizeof(value));
    return value;
}


Register::Register() : kind_(UL_REG_TYPE_UNKNOWN) {
    memset(data_, 0, sizeof(data_));
}


Register::Register(const void *buffer, RegisterDataType kind) : kind_(kind) {
    assign_value(buffer, kind);
}


void Register::assign_value(const void *buffer, RegisterDataType kind) {
    memcpy(data_, buffer, size_for_register_kind(kind));
    kind_ = kind;
}


RegisterDataType Register::get_kind() const noexcept { return kind_; }


size_t Register::get_size() const { return size_for_register_kind(kind_); }


size_t Register::size_for_register_kind(RegisterDataType kind) {
    switch (kind) {
        case UL_REG_TYPE_INT8:
            return 1;
        case UL_REG_TYPE_INT16:
            return 2;
        case UL_REG_TYPE_INT32:
        case UL_REG_TYPE_FLOAT32:
            return 4;
        case UL_REG_TYPE_INT64:
        case UL_REG_TYPE_FLOAT64:
        case UL_REG_TYPE_INT8_ARRAY_8:
        case UL_REG_TYPE_INT16_ARRAY_4:
        case UL_REG_TYPE_INT32_ARRAY_2:
        case UL_REG_TYPE_INT64_ARRAY_1:
            return 8;
        case UL_REG_TYPE_FLOAT80:
            return 10;
        case UL_REG_TYPE_INT8_ARRAY_16:
        case UL_REG_TYPE_INT16_ARRAY_8:
        case UL_REG_TYPE_INT32_ARRAY_4:
        case UL_REG_TYPE_INT64_ARRAY_2:
        case UL_REG_TYPE_FLOAT32_ARRAY_4:
        case UL_REG_TYPE_FLOAT64_ARRAY_2:
            return 16;
        case UL_REG_TYPE_INT8_ARRAY_32:
        case UL_REG_TYPE_INT16_ARRAY_16:
        case UL_REG_TYPE_INT32_ARRAY_8:
        case UL_REG_TYPE_INT64_ARRAY_4:
        case UL_REG_TYPE_FLOAT32_ARRAY_8:
        case UL_REG_TYPE_FLOAT64_ARRAY_4:
            return 32;
        case UL_REG_TYPE_INT8_ARRAY_64:
        case UL_REG_TYPE_INT16_ARRAY_32:
        case UL_REG_TYPE_INT32_ARRAY_16:
        case UL_REG_TYPE_INT64_ARRAY_8:
        case UL_REG_TYPE_FLOAT32_ARRAY_16:
        case UL_REG_TYPE_FLOAT64_ARRAY_8:
            return 64;
        case UL_REG_TYPE_UNKNOWN:
            throw LuaBindingError("Can't determine size of register type \"UNKNOWN\",");
        default:
            throw std::invalid_argument("Invalid register type.");
    }
}


int8_t Register::as_int8() const noexcept {
    return *reinterpret_cast<const int8_t *>(data_);
}


int16_t Register::as_int16() const noexcept {
    return *reinterpret_cast<const int16_t *>(data_);
}


int32_t Register::as_int32() const noexcept {
    return *reinterpret_cast<const int32_t *>(data_);
}


int64_t Register::as_int64() const noexcept {
    return *reinterpret_cast<const int64_t *>(data_);
}


uclua_float32 Register::as_float32() const noexcept {
    return *reinterpret_cast<const uclua_float32 *>(data_);
}


uclua_float64 Register::as_float64() const noexcept {
    return *reinterpret_cast<const uclua_float64 *>(data_);
}


uclua_float80 Register::as_float80() const {
    throw LuaBindingError(
        "Error: Writing 80-bit floating-point numbers is currently not supported."
    );
    //return read_float80(data_);
}


std::array<int8_t, 8> Register::as_8xi8() const {
    return array_cast<int8_t, 8>();
}


std::array<int16_t, 4> Register::as_4xi16() const {
    return array_cast<int16_t, 4>();
}


std::array<int32_t, 2> Register::as_2xi32() const {
    return array_cast<int32_t, 2>();
}


std::array<int64_t, 1> Register::as_1xi64() const {
    return array_cast<int64_t, 1>();
}


std::array<uclua_float32, 4> Register::as_4xf32() const {
    return array_cast<uclua_float32 , 4>();
}


std::array<uclua_float64, 2> Register::as_2xf64() const {
    return array_cast<uclua_float64 , 2>();
}


std::array<int8_t, 16> Register::as_16xi8() const {
    return array_cast<int8_t, 16>();
}


std::array<int16_t, 8> Register::as_8xi16() const {
    return array_cast<int16_t, 8>();
}


std::array<int32_t, 4> Register::as_4xi32() const {
    return array_cast<int32_t, 4>();
}


std::array<int64_t, 2> Register::as_2xi64() const {
    return array_cast<int64_t, 2>();
}


std::array<uclua_float32, 8> Register::as_8xf32() const {
    return array_cast<uclua_float32, 8>();
}


std::array<uclua_float64, 4> Register::as_4xf64() const {
    return array_cast<uclua_float64, 4>();
}


std::array<int8_t, 32> Register::as_32xi8() const {
    return array_cast<int8_t, 32>();
}


std::array<int16_t, 16> Register::as_16xi16() const {
    return array_cast<int16_t, 16>();
}


std::array<int32_t, 8> Register::as_8xi32() const {
    return array_cast<int32_t, 8>();
}


std::array<int64_t, 4> Register::as_4xi64() const {
    return array_cast<int64_t, 4>();
}


std::array<int8_t, 64> Register::as_64xi8() const {
    return array_cast<int8_t, 64>();
}


std::array<int16_t, 32> Register::as_32xi16() const {
    return array_cast<int16_t, 32>();
}


std::array<int32_t, 16> Register::as_16xi32() const {
    return array_cast<int32_t, 16>();
}


std::array<int64_t, 8> Register::as_8xi64() const {
    return array_cast<int64_t, 8>();
}


std::array<uclua_float64, 8> Register::as_8xf64() const {
    return array_cast<uclua_float64, 8>();
}


std::array<uclua_float32, 16> Register::as_16xf32() const {
    return array_cast<uclua_float32, 16>();
}


void Register::push_to_lua(lua_State *L) const {
    switch (kind_) {
        case UL_REG_TYPE_INT8:
            lua_pushinteger(L, this->as_int8());
            break;
        case UL_REG_TYPE_INT16:
            lua_pushinteger(L, this->as_int16());
            break;
        case UL_REG_TYPE_INT32:
            lua_pushinteger(L, this->as_int32());
            break;
        case UL_REG_TYPE_FLOAT32:
            lua_pushnumber(L, this->as_float32());
            break;
        case UL_REG_TYPE_INT64:
            lua_pushinteger(L, this->as_int64());
            break;
        case UL_REG_TYPE_FLOAT64:
            lua_pushnumber(L, this->as_float64());
            break;
        case UL_REG_TYPE_INT8_ARRAY_8:
            integer_array_to_table(L, this->as_8xi8());
            break;
        case UL_REG_TYPE_INT16_ARRAY_4:
            integer_array_to_table(L, this->as_4xi16());
            break;
        case UL_REG_TYPE_INT32_ARRAY_2:
            integer_array_to_table(L, this->as_2xi32());
            break;
        case UL_REG_TYPE_INT64_ARRAY_1:
            lua_createtable(L, 1, 0);
            // FIXME (dargueta): This invokes undefined behavior for 32-bit Lua
            lua_pushinteger(L, this->as_int64());
            lua_seti(L, -2, 1);
            break;
        case UL_REG_TYPE_FLOAT80:
            throw LuaBindingError(
                "Error: Reading 80-bit floating-point numbers is currently not"
                " supported."
            );
            /*
            // Probably gonna lose precision here
            lua_pushnumber(L, this->as_float80());
            break;
            */
        case UL_REG_TYPE_INT8_ARRAY_16:
            integer_array_to_table(L, this->as_16xi8());
            break;
        case UL_REG_TYPE_INT16_ARRAY_8:
            integer_array_to_table(L, this->as_8xi16());
            break;
        case UL_REG_TYPE_INT32_ARRAY_4:
            integer_array_to_table(L, this->as_4xi32());
            break;
        case UL_REG_TYPE_INT64_ARRAY_2:
            integer_array_to_table(L, this->as_2xi64());
            break;
        case UL_REG_TYPE_FLOAT32_ARRAY_4:
            float_array_to_table(L, this->as_4xf32());
            break;
        case UL_REG_TYPE_FLOAT64_ARRAY_2:
            float_array_to_table(L, this->as_2xf64());
            break;
        case UL_REG_TYPE_INT8_ARRAY_32:
            integer_array_to_table(L, this->as_32xi8());
            break;
        case UL_REG_TYPE_INT16_ARRAY_16:
            integer_array_to_table(L, this->as_16xi16());
            break;
        case UL_REG_TYPE_INT32_ARRAY_8:
            integer_array_to_table(L, this->as_8xi32());
            break;
        case UL_REG_TYPE_INT64_ARRAY_4:
            integer_array_to_table(L, this->as_4xi64());
            break;
        case UL_REG_TYPE_FLOAT32_ARRAY_8:
            float_array_to_table(L, this->as_8xf32());
            break;
        case UL_REG_TYPE_FLOAT64_ARRAY_4:
            float_array_to_table(L, this->as_4xf64());
            break;
        case UL_REG_TYPE_INT8_ARRAY_64:
            integer_array_to_table(L, this->as_64xi8());
            break;
        case UL_REG_TYPE_INT32_ARRAY_16:
            integer_array_to_table(L, this->as_16xi32());
            break;
        case UL_REG_TYPE_INT64_ARRAY_8:
            integer_array_to_table(L, this->as_8xi64());
            break;
        case UL_REG_TYPE_FLOAT32_ARRAY_16:
            float_array_to_table(L, this->as_16xf32());
            break;
        case UL_REG_TYPE_FLOAT64_ARRAY_8:
            float_array_to_table(L, this->as_8xf64());
            break;
        case UL_REG_TYPE_INT16_ARRAY_32:
            integer_array_to_table(L, this->as_32xi16());
            break;
        case UL_REG_TYPE_UNKNOWN:
        default:
            throw LuaBindingError("Register is uninitialized or has no known type.");
    }
}


/**
 * Cast @a value to type @a T, or throw an exception if it exceeds the range of
 * representable values.
 *
 * @tparam T The type to cast @a value to.
 * @param value The value to convert.
 *
 * @return @a value cast to type @a T.
 */
template <typename T>
T try_cast(lua_Integer value) {
    auto ext_value = static_cast<intmax_t>(value);

    constexpr intmax_t min = std::numeric_limits<T>::min();
    constexpr intmax_t max = std::numeric_limits<T>::max();
    if ((ext_value >= min) && (ext_value <= max))
        return static_cast<T>(value);

    // If we get here then `value` isn't representable as a T.
    auto buf = std::ostringstream();
    buf << "Numeric value out of range: " << value << " is not within ["
        << min << ", " << max << "].";

    throw std::domain_error(buf.str());
}


/**
 * Read a Lua integer from the stack and write it to @a buffer as a type @a T.
 *
 * @tparam T
 * @param L
 * @param value_index
 * @param buffer
 */
template<typename T>
void write_lua_integer(lua_State *L, int value_index, void *buffer) {
    lua_Integer lua_int = lua_tointeger(L, value_index);
    T native_value = try_cast<T>(lua_int);
    *reinterpret_cast<T *>(buffer) = native_value;
}


/**
 * Write a sequence of Lua integers from a table into a buffer.
 *
 * All values in the table must be representable as a @a T. If any value exceeds
 * the type's minimum or maximum values, the function throws an exception.
 *
 * @tparam T
 * @param L
 * @param table_index
 * @param n_elements
 * @param buffer
 */
template<typename T>
void write_lua_integer_array(
    lua_State *L, int table_index, int n_elements, void *buffer
) {
    for (int i = 0; i < n_elements; ++i) {
        lua_geti(L, table_index, i + 1);
        write_lua_integer<T>(
            L,
            -1,
            reinterpret_cast<T *>(buffer) + i
        );
        lua_pop(L, 1);
    }
}


Register Register::from_lua(lua_State *L, int value_index, int kind_index) {
    int i;
    register_buffer_type buffer;
    auto kind = static_cast<RegisterDataType>(lua_tointeger(L, kind_index));

    switch (kind) {
        case UL_REG_TYPE_INT8:
            write_lua_integer<int8_t>(L, value_index, buffer);
            break;
        case UL_REG_TYPE_INT16:
            write_lua_integer<int16_t>(L, value_index, buffer);
            break;
        case UL_REG_TYPE_INT32:
            write_lua_integer<int32_t>(L, value_index, buffer);
            break;
        case UL_REG_TYPE_FLOAT32:
            *reinterpret_cast<uclua_float32 *>(buffer) =
                static_cast<uclua_float32>(lua_tonumber(L, value_index));
            break;
        case UL_REG_TYPE_INT64:
            write_lua_integer<int64_t>(L, value_index, buffer);
            break;
        case UL_REG_TYPE_FLOAT64:
            *reinterpret_cast<uclua_float64 *>(buffer) =
                static_cast<uclua_float64>(lua_tonumber(L, value_index));
            break;
        case UL_REG_TYPE_INT8_ARRAY_8:
            write_lua_integer_array<int8_t>(L, value_index, 8, buffer);
            break;
        case UL_REG_TYPE_INT16_ARRAY_4:
            write_lua_integer_array<int16_t>(L, value_index, 4, buffer);
            break;
        case UL_REG_TYPE_INT32_ARRAY_2:
            write_lua_integer_array<int32_t>(L, value_index, 2, buffer);
            break;
        case UL_REG_TYPE_INT64_ARRAY_1:
            write_lua_integer_array<int64_t>(L, value_index, 1, buffer);
            break;
        case UL_REG_TYPE_FLOAT80:
            write_float80(lua_tonumber(L, value_index), buffer);
            break;
        case UL_REG_TYPE_INT8_ARRAY_16:
            write_lua_integer_array<int8_t>(L, value_index, 16, buffer);
            break;
        case UL_REG_TYPE_INT16_ARRAY_8:
            write_lua_integer_array<int16_t>(L, value_index, 8, buffer);
            break;
        case UL_REG_TYPE_INT32_ARRAY_4:
            write_lua_integer_array<int32_t>(L, value_index, 4, buffer);
            break;
        case UL_REG_TYPE_INT64_ARRAY_2:
            write_lua_integer_array<int64_t>(L, value_index, 2, buffer);
            break;
        case UL_REG_TYPE_FLOAT32_ARRAY_4:
            for (i = 0; i < 4; ++i) {
                lua_geti(L, value_index, i + 1);
                reinterpret_cast<uclua_float32 *>(buffer)[i] =
                    static_cast<uclua_float32>(lua_tonumber(L, -1));
                lua_pop(L, 1);
            }
            break;
        case UL_REG_TYPE_FLOAT64_ARRAY_2:
            for (i = 0; i < 2; ++i) {
                lua_geti(L, value_index, i + 1);
                reinterpret_cast<uclua_float64 *>(buffer)[i] =
                    static_cast<uclua_float64>(lua_tonumber(L, -1));
                lua_pop(L, 1);
            }
            break;
        case UL_REG_TYPE_INT8_ARRAY_32:
            write_lua_integer_array<int8_t>(L, value_index, 32, buffer);
            break;
        case UL_REG_TYPE_INT16_ARRAY_16:
            write_lua_integer_array<int16_t>(L, value_index, 16, buffer);
            break;
        case UL_REG_TYPE_INT32_ARRAY_8:
            write_lua_integer_array<int32_t>(L, value_index, 8, buffer);
            break;
        case UL_REG_TYPE_INT64_ARRAY_4:
            write_lua_integer_array<int64_t>(L, value_index, 4, buffer);
            break;
        case UL_REG_TYPE_FLOAT32_ARRAY_8:
            for (i = 0; i < 8; ++i) {
                lua_geti(L, value_index, i + 1);
                reinterpret_cast<uclua_float32 *>(buffer)[i] =
                    static_cast<uclua_float32>(lua_tonumber(L, -1));
                lua_pop(L, 1);
            }
            break;
        case UL_REG_TYPE_FLOAT64_ARRAY_4:
            for (i = 0; i < 4; ++i) {
                lua_geti(L, value_index, i + 1);
                reinterpret_cast<uclua_float64 *>(buffer)[i] =
                    static_cast<uclua_float64>(lua_tonumber(L, -1));
                lua_pop(L, 1);
            }
            break;
        case UL_REG_TYPE_INT8_ARRAY_64:
            write_lua_integer_array<int8_t>(L, value_index, 64, buffer);
            break;
        case UL_REG_TYPE_INT16_ARRAY_32:
            write_lua_integer_array<int16_t>(L, value_index, 32, buffer);
            break;
        case UL_REG_TYPE_INT32_ARRAY_16:
            write_lua_integer_array<int32_t>(L, value_index, 16, buffer);
            break;
        case UL_REG_TYPE_INT64_ARRAY_8:
            write_lua_integer_array<int64_t>(L, value_index, 8, buffer);
            break;
        case UL_REG_TYPE_FLOAT32_ARRAY_16:
            for (i = 0; i < 16; ++i) {
                lua_geti(L, value_index, i + 1);
                reinterpret_cast<uclua_float32 *>(buffer)[i] =
                    static_cast<uclua_float32>(lua_tonumber(L, -1));
                lua_pop(L, 1);
            }
            break;
        case UL_REG_TYPE_FLOAT64_ARRAY_8:
            for (i = 0; i < 8; ++i) {
                lua_geti(L, value_index, i + 1);
                reinterpret_cast<uclua_float64 *>(buffer)[i] =
                    static_cast<uclua_float64>(lua_tonumber(L, -1));
                lua_pop(L, 1);
            }
            break;

        case UL_REG_TYPE_UNKNOWN:
        default:
            throw LuaBindingError("Invalid register type ID.");
    }

    return {buffer, kind};
}


int ul_reg_write(lua_State *L) {
    uc_engine *engine = ul_toengine(L, 1);
    int register_id = static_cast<int>(luaL_checkinteger(L, 2));
    register_buffer_type buffer;

    memset(buffer, 0, sizeof(buffer));
    *reinterpret_cast<int_least64_t *>(buffer) =
        static_cast<int_least64_t>(luaL_checkinteger(L, 3));

    uc_err error = uc_reg_write(engine, register_id, buffer);
    if (error != UC_ERR_OK)
        return ul_crash_on_error(L, error);
    return 0;
}


int ul_reg_write_as(lua_State *L) {
    uc_engine *engine = ul_toengine(L, 1);
    int register_id = static_cast<int>(luaL_checkinteger(L, 2));
    Register reg = Register::from_lua(L, 3, 4);

    uc_err error = uc_reg_write(engine, register_id, reg.data_);
    if (error != UC_ERR_OK)
        return ul_crash_on_error(L, error);
    return 0;
}


int ul_reg_read(lua_State *L) {
    register_buffer_type value_buffer;
    memset(value_buffer, 0, sizeof(value_buffer));

    uc_engine *engine = ul_toengine(L, 1);
    int register_id = static_cast<int>(luaL_checkinteger(L, 2));

    // When reading an MSR on an x86 processor, Unicorn requires the buffer to
    // contain the ID of the register to read.
    if (register_id == UC_X86_REG_MSR) {
        if (lua_gettop(L) < 3) {
            throw LuaBindingError(
                "Reading an x86 model-specific register (MSR) requires"
                " an additional argument identifying the register to read. You"
                " can find a list of these in the \"Intel 64 and IA-32 Software"
                " Developer's Manual\", available as PDFs from their website."
            );
        }
        int msr_id = static_cast<int>(luaL_checkinteger(L, 3));
        *reinterpret_cast<int *>(value_buffer) = msr_id;
    }

    uc_err error = uc_reg_read(engine, register_id, value_buffer);
    if (error != UC_ERR_OK)
        return ul_crash_on_error(L, error);

    lua_pushinteger(L, *reinterpret_cast<lua_Integer *>(value_buffer));
    return 1;
}


int ul_reg_read_as(lua_State *L) {
    uc_engine *engine = ul_toengine(L, 1);
    int register_id = static_cast<int>(luaL_checkinteger(L, 2));
    auto read_as_type = static_cast<RegisterDataType>(luaL_checkinteger(L, 3));

    if (register_id == UC_X86_REG_MSR) {
        throw LuaBindingError(
            "reg_read_as() doesn't support reading x86 model-specific"
            " registers."
        );
    }

    register_buffer_type value_buffer;
    memset(value_buffer, 0, sizeof(value_buffer));

    uc_err error = uc_reg_read(engine, register_id, value_buffer);
    if (error != UC_ERR_OK)
        return ul_crash_on_error(L, error);

    Register register_obj(value_buffer, read_as_type);
    register_obj.push_to_lua(L);

    return 1;
}


int ul_reg_write_batch(lua_State *L) {
    uc_engine *engine = ul_toengine(L, 1);

    /* Second argument will be a table with key-value pairs, the keys being the
     * registers to write to and the values being the values to write to the
     * corresponding registers. */
    size_t n_registers = count_table_elements(L, 2);

    std::unique_ptr<int[]> register_ids(new int[n_registers]);
    std::unique_ptr<int_least64_t[]> values(new int_least64_t[n_registers]);
    std::unique_ptr<void *[]> p_values(new void *[n_registers]);

    /* Iterate through the register/value pairs and put them in the corresponding
     * array positions. */
    lua_pushnil(L);
    for (size_t i = 0; lua_next(L, 2) != 0; ++i) {
        register_ids[i] = static_cast<int>(luaL_checkinteger(L, -2));
        values[i] = static_cast<int_least64_t>(luaL_checkinteger(L, -1));
        p_values[i] = &values[i];
        lua_pop(L, 1);
    }

    uc_err error = uc_reg_write_batch(
        engine,
        register_ids.get(),
        p_values.get(),
        static_cast<int>(n_registers)
    );
    if (error != UC_ERR_OK)
        return ul_crash_on_error(L, error);
    return 0;
}


static void prepare_batch_buffers(
    size_t n_registers,
    std::unique_ptr<register_buffer_type[]>& values,
    std::unique_ptr<void *[]>& value_pointers
) {
    values.reset(new register_buffer_type[n_registers]);
    value_pointers.reset(new void *[n_registers]);

    for (size_t i = 0; i < n_registers; ++i)
        value_pointers[i] = &values[i];
    memset(values.get(), 0, n_registers * sizeof(register_buffer_type));
}


int ul_reg_read_batch(lua_State *L) {
    uc_engine *engine = ul_toengine(L, 1);
    auto n_registers = static_cast<size_t>(lua_gettop(L)) - 1;

    std::unique_ptr<int[]> register_ids(new int[n_registers]);
    std::unique_ptr<register_buffer_type[]> values;
    std::unique_ptr<void *[]> value_pointers;

    prepare_batch_buffers(n_registers, values, value_pointers);
    for (size_t i = 0; i < n_registers; ++i)
        register_ids[i] = static_cast<int>(lua_tointeger(L, static_cast<int>(i) + 2));

    uc_err error = uc_reg_read_batch(
        engine,
        register_ids.get(),
        value_pointers.get(),
        static_cast<int>(n_registers)
    );
    if (error != UC_ERR_OK)
        return ul_crash_on_error(L, error);

    for (size_t i = 0; i < n_registers; ++i) {
        lua_pushinteger(
            L,
            *reinterpret_cast<lua_Integer *>(values[i])
        );
    }
    return static_cast<int>(n_registers);
}


int ul_reg_read_batch_as(lua_State *L) {
    uc_engine *engine = ul_toengine(L, 1);
    size_t n_registers = count_table_elements(L, 2);

    std::unique_ptr<int[]> register_ids(new int[n_registers]);
    std::unique_ptr<int[]> value_types(new int[n_registers]);
    std::unique_ptr<register_buffer_type[]> values;
    std::unique_ptr<void *[]> value_pointers;

    prepare_batch_buffers(n_registers, values, value_pointers);

    // Iterate through the second argument -- a table mapping register IDs to
    // the types we want them back as.
    lua_pushnil(L);
    for (size_t i = 0; lua_next(L, 2) != 0; ++i) {
        register_ids[i] = (int)luaL_checkinteger(L, -2);
        value_types[i] = (int)luaL_checkinteger(L, -1);
        lua_pop(L, 1);
    }

    uc_err error = uc_reg_read_batch(
        engine,
        register_ids.get(),
        value_pointers.get(),
        static_cast<int>(n_registers)
    );
    if (error != UC_ERR_OK)
        return ul_crash_on_error(L, error);

    // Create the table we're going to return the register values in. The result
    // is a key-value mapping where the keys are the register IDs and the values
    // are the typecasted values read from the registers.
    lua_createtable(L, 0, static_cast<int>(n_registers));
    for (size_t i = 0; i < n_registers; ++i) {
        // Key: register ID
        lua_pushinteger(L, register_ids[i]);

        // Value: Deserialized register
        auto register_object = Register(
            value_pointers[i],
            static_cast<RegisterDataType>(value_types[i])
        );
        register_object.push_to_lua(L);
        lua_settable(L, -3);
    }

    return 1;
}
