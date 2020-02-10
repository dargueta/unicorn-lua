#include <array>
#include <cerrno>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <memory>

#include <unicorn/unicorn.h>

#include "unicornlua/compat.h"
#include "unicornlua/engine.h"
#include "unicornlua/errors.h"
#include "unicornlua/lua.h"
#include "unicornlua/registers.h"
#include "unicornlua/utils.h"


uclua_float80 read_float80(const uint8_t *data) {
    uint64_t significand = *reinterpret_cast<const uint64_t *>(data);
    int exponent = *reinterpret_cast<const uint16_t *>(data + 8) & 0x7fff;
    bool sign = (*reinterpret_cast<const uint16_t *>(data + 8) & 0x8000) != 0;

    uclua_float80 signed_significand = significand;
    if (sign)
        signed_significand *= -1;

    // Clear errno before starting because we use it to indicate that the return
    // value is valid on some FPUs but not others, or if the NaN is a signaling
    // one.
    errno = 0;

    if (exponent == 0) {
        if (significand == 0)
            return 0.0;
        return ldexp(signed_significand, -16382);
    }
    else if (exponent == 0x7fff) {
        // Top two bits of the significand will tell us what kind of number this
        // is and aren't used for storing a value.
        switch ((significand >> 62) & 3) {
            case 0:
                if (significand == 0)
                    return sign ? -INFINITY : +INFINITY;

                // Significand is non-zero, fall through to next case.
                // Clang for some reason doesn't like this directive but GCC needs
                // it so we skip it if we're on Clang.
                #ifndef __clang__
                    __attribute__ ((fallthrough));
                #endif
            case 1:
                /* 8087 - 80287 treat this as a signaling NaN, 80387 and later
                 * treat this as an invalid operand and will explode. Compromise
                 * by setting errno and returning NaN instead of throwing an
                 * exception.
                 */
                errno = EINVAL;
                return NAN;
            case 2:
                if ((significand & 0x3fffffffffffffffULL) == 0)
                    return sign ? -INFINITY : +INFINITY;

                // Else: This is a signaling NaN. We don't want to throw an
                // exception because Lua is just reading the registers of the
                // processor, not using them.
                errno = EDOM;
                return NAN;
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

    // Regular number!
    if (significand & 0x8000000000000000ULL)
        // Normalized value. Clear the high bit of the significand.
        return ldexp(signed_significand - 0x8000000000000000ULL, exponent - 16383);

    // Unnormal number. Invalid on 80387+; 80287 and earlier use a different
    // exponent bias.
    errno = EINVAL;
    return ldexp(signed_significand, exponent - 16382);
}


void write_float80(uclua_float80 value, uint8_t *buffer) {
    int f_type = std::fpclassify(value);
    uint16_t sign_bit = std::signbit(value) ? 0x8000 : 0;

    switch (f_type) {
        case FP_INFINITE:
            // TODO (dargueta): This won't work on a big-endian machine
            *reinterpret_cast<uint64_t *>(buffer) = 0x8000000000000000;
            *reinterpret_cast<uint16_t *>(buffer + 8) = 0x7fff | sign_bit;
            return;
        case FP_NAN:
            *reinterpret_cast<uint64_t *>(buffer) = 0xffffffffffffffff;
            *reinterpret_cast<uint16_t *>(buffer + 8) = 0xffff;
            return;
        case FP_ZERO:
            *reinterpret_cast<uint64_t *>(buffer) = 0;
            *reinterpret_cast<uint16_t *>(buffer + 8) = 0;
            return;
        case FP_SUBNORMAL:
        case FP_NORMAL:
            break;
        default:
            throw std::runtime_error(
                "Unrecognized value returned from std::fpclassify(). This library was"
                " probably compiled on a newer standard of C++ than it was written for."
                " Please file a bug ticket."
            );
    }

    int exponent;
    uclua_float80 float_significand = frexp(value, &exponent);

    if ((exponent <= -16383) || (exponent >= 16384))
        throw std::domain_error(
            "Can't convert value outside representable range for 80-bit float without"
            " loss of precision."
        );

    // The high bit of the significand is always set for normal numbers, and clear for
    // denormal numbers. This means the significand is 63 bits, not 64, hence why we
    // multiply here by 2^63 and not 2^64.
    uint64_t int_significand = float_significand * 2e63;
    if (f_type == FP_NORMAL) {
        int_significand |= 0x8000000000000000ULL;
        exponent += 16383;
    }
    else
        exponent = 0;

    *reinterpret_cast<uint64_t *>(buffer) = int_significand;
    *reinterpret_cast<uint16_t *>(buffer + 8) = ((uint16_t)exponent) | sign_bit;
}


template <class T, int N>
std::array<T, N> Register::array_cast() const {
    std::array<T, N> value{};
    memcpy(value.data(), data_, value.size());
    return value;
}


Register::Register() : kind_(UL_REG_TYPE_UNKNOWN) {}


Register::Register(const void *buffer, RegisterDataType kind) {
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
    return read_float80(data_);
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
    int i;

    std::array<int16_t, 16> values_16xi16;
    std::array<int16_t, 4> values_4xi16;
    std::array<int16_t, 8> values_8xi16;
    std::array<int32_t, 16> values_16xi32;
    std::array<int32_t, 2> values_2xi32;
    std::array<int32_t, 4> values_4xi32;
    std::array<int32_t, 8> values_8xi32;
    std::array<int64_t, 2> values_2xi64;
    std::array<int64_t, 4> values_4xi64;
    std::array<int64_t, 8> values_8xi64;
    std::array<int8_t, 16> values_16xi8;
    std::array<int8_t, 32> values_32xi8;
    std::array<int8_t, 64> values_64xi8;
    std::array<int8_t, 8> values_8xi8;
    std::array<uclua_float32, 16> values_16xf32;
    std::array<uclua_float32, 4> values_4xf32;
    std::array<uclua_float32, 8> values_8xf32;
    std::array<uclua_float64, 2> values_2xf64;
    std::array<uclua_float64, 4> values_4xf64;
    std::array<uclua_float64, 8> values_8xf64;

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
            values_8xi8 = this->as_8xi8();
            lua_createtable(L, 8, 0);
            for (i = 0; i < 8; ++i) {
                lua_pushinteger(L, values_8xi8[i]);
                lua_seti(L, -2, i + 1);
            }
            break;
        case UL_REG_TYPE_INT16_ARRAY_4:
            values_4xi16 = this->as_4xi16();
            lua_createtable(L, 4, 0);
            for (i = 0; i < 4; ++i) {
                lua_pushinteger(L, values_4xi16[i]);
                lua_seti(L, -2, i + 1);
            }
            break;
        case UL_REG_TYPE_INT32_ARRAY_2:
            values_2xi32 = this->as_2xi32();
            lua_createtable(L, 2, 0);
            for (i = 0; i < 2; ++i) {
                lua_pushinteger(L, values_2xi32[i]);
                lua_seti(L, -2, i + 1);
            }
            break;
        case UL_REG_TYPE_INT64_ARRAY_1:
            lua_createtable(L, 1, 0);
            lua_pushinteger(L, this->as_int64());
            lua_seti(L, -2, 1);
            break;
        case UL_REG_TYPE_FLOAT80:
            /* Probably gonna lose precision here */
            lua_pushnumber(L, this->as_float80());
            break;
        case UL_REG_TYPE_INT8_ARRAY_16:
            values_16xi8 = this->as_16xi8();
            lua_createtable(L, 16, 0);
            for (i = 0; i < 16; ++i) {
                lua_pushinteger(L, values_16xi8[i]);
                lua_seti(L, -2, i + 1);
            }
            break;
        case UL_REG_TYPE_INT16_ARRAY_8:
            values_8xi16 = this->as_8xi16();
            lua_createtable(L, 8, 0);
            for (i = 0; i < 8; ++i) {
                lua_pushinteger(L, values_8xi16[i]);
                lua_seti(L, -2, i + 1);
            }
            break;
        case UL_REG_TYPE_INT32_ARRAY_4:
            values_4xi32 = this->as_4xi32();
            lua_createtable(L, 4, 0);
            for (i = 0; i < 4; ++i) {
                lua_pushinteger(L, values_4xi32[i]);
                lua_seti(L, -2, i + 1);
            }
            break;
        case UL_REG_TYPE_INT64_ARRAY_2:
            values_2xi64 = this->as_2xi64();
            lua_createtable(L, 2, 0);
            for (i = 0; i < 2; ++i) {
                lua_pushinteger(L, values_2xi64[i]);
                lua_seti(L, -2, i + 1);
            }
            break;
        case UL_REG_TYPE_FLOAT32_ARRAY_4:
            values_4xf32 = this->as_4xf32();
            lua_createtable(L, 4, 0);
            for (i = 0; i < 4; ++i) {
                lua_pushinteger(L, values_4xf32[i]);
                lua_seti(L, -2, i + 1);
            }
            break;
        case UL_REG_TYPE_FLOAT64_ARRAY_2:
            values_2xf64 = this->as_2xf64();
            lua_createtable(L, 2, 0);
            for (i = 0; i < 2; ++i) {
                lua_pushinteger(L, values_2xf64[i]);
                lua_seti(L, -2, i + 1);
            }
            break;
        case UL_REG_TYPE_INT8_ARRAY_32:
            values_32xi8 = this->as_32xi8();
            lua_createtable(L, 32, 0);
            for (i = 0; i < 32; ++i) {
                lua_pushinteger(L, values_32xi8[i]);
                lua_seti(L, -2, i + 1);
            }
            break;
        case UL_REG_TYPE_INT16_ARRAY_16:
            values_16xi16 = this->as_16xi16();
            lua_createtable(L, 16, 0);
            for (i = 0; i < 16; ++i) {
                lua_pushinteger(L, values_16xi16[i]);
                lua_seti(L, -2, i + 1);
            }
            break;
        case UL_REG_TYPE_INT32_ARRAY_8:
            values_8xi32 = this->as_8xi32();
            lua_createtable(L, 8, 0);
            for (i = 0; i < 8; ++i) {
                lua_pushinteger(L, values_8xi32[i]);
                lua_seti(L, -2, i + 1);
            }
            break;
        case UL_REG_TYPE_INT64_ARRAY_4:
            values_4xi64 = this->as_4xi64();
            lua_createtable(L, 4, 0);
            for (i = 0; i < 4; ++i) {
                lua_pushinteger(L, values_4xi64[i]);
                lua_seti(L, -2, i + 1);
            }
            break;
        case UL_REG_TYPE_FLOAT32_ARRAY_8:
            values_8xf32 = this->as_8xf32();
            lua_createtable(L, 8, 0);
            for (i = 0; i < 8; ++i) {
                lua_pushinteger(L, values_8xf32[i]);
                lua_seti(L, -2, i + 1);
            }
            break;
        case UL_REG_TYPE_FLOAT64_ARRAY_4:
            values_4xf64 = this->as_4xf64();
            lua_createtable(L, 4, 0);
            for (i = 0; i < 4; ++i) {
                lua_pushinteger(L, values_4xf64[i]);
                lua_seti(L, -2, i + 1);
            }
            break;
        case UL_REG_TYPE_INT8_ARRAY_64:
            values_64xi8 = this->as_64xi8();
            lua_createtable(L, 64, 0);
            for (i = 0; i < 64; ++i) {
                lua_pushinteger(L, values_64xi8[i]);
                lua_seti(L, -2, i + 1);
            }
            break;
        case UL_REG_TYPE_INT32_ARRAY_16:
            values_16xi32 = this->as_16xi32();
            lua_createtable(L, 16, 0);
            for (i = 0; i < 16; ++i) {
                lua_pushinteger(L, values_16xi32[i]);
                lua_seti(L, -2, i + 1);
            }
            break;
        case UL_REG_TYPE_INT64_ARRAY_8:
            values_8xi64 = this->as_8xi64();
            lua_createtable(L, 8, 0);
            for (i = 0; i < 8; ++i) {
                lua_pushinteger(L, values_8xi64[i]);
                lua_seti(L, -2, i + 1);
            }
            break;
        case UL_REG_TYPE_FLOAT32_ARRAY_16:
            values_16xf32 = this->as_16xf32();
            lua_createtable(L, 16, 0);
            for (i = 0; i < 16; ++i) {
                lua_pushinteger(L, values_16xf32[i]);
                lua_seti(L, -2, i + 1);
            }
            break;
        case UL_REG_TYPE_FLOAT64_ARRAY_8:
            values_8xf64 = this->as_8xf64();
            lua_createtable(L, 8, 0);
            for (i = 0; i < 8; ++i) {
                lua_pushinteger(L, values_8xf64[i]);
                lua_seti(L, -2, i + 1);
            }
            break;

        case UL_REG_TYPE_UNKNOWN:
        default:
            /* Invalid register type */
            lua_pushnil(L);
            break;
    }
}


Register Register::from_lua(lua_State *L, int value_index, int kind_index) {
    int i;
    register_buffer_type buffer;
    auto kind = static_cast<RegisterDataType>(lua_tointeger(L, kind_index));

    switch (kind) {
        case UL_REG_TYPE_INT8:
            *(int8_t *)buffer = lua_tointeger(L, value_index);
            break;
        case UL_REG_TYPE_INT16:
            *(int16_t *)buffer = lua_tointeger(L, value_index);
            break;
        case UL_REG_TYPE_INT32:
            *(int32_t *)buffer = lua_tointeger(L, value_index);
            break;
        case UL_REG_TYPE_FLOAT32:
            *(uclua_float32 *)buffer = lua_tonumber(L, value_index);
            break;
        case UL_REG_TYPE_INT64:
            *(int64_t *)buffer = lua_tointeger(L, value_index);
            break;
        case UL_REG_TYPE_FLOAT64:
            *(uclua_float64 *)buffer = lua_tonumber(L, value_index);
            break;
        case UL_REG_TYPE_INT8_ARRAY_8:
            for (i = 0; i < 8; ++i) {
                lua_geti(L, value_index, i + 1);
                ((int8_t *)buffer)[i] = lua_tointeger(L, -1);
                lua_pop(L, 1);
            }
            break;
        case UL_REG_TYPE_INT16_ARRAY_4:
            for (i = 0; i < 4; ++i) {
                lua_geti(L, value_index, i + 1);
                ((int16_t *)buffer)[i] = lua_tointeger(L, -1);
                lua_pop(L, 1);
            }
            break;
        case UL_REG_TYPE_INT32_ARRAY_2:
            for (i = 0; i < 2; ++i) {
                lua_geti(L, value_index, i + 1);
                ((int32_t *)buffer)[i] = lua_tointeger(L, -1);
                lua_pop(L, 1);
            }
            break;
        case UL_REG_TYPE_INT64_ARRAY_1:
            lua_geti(L, value_index, 1);
            *(int64_t *)buffer = lua_tointeger(L, -1);
            lua_pop(L, 1);
            break;
        case UL_REG_TYPE_FLOAT80:
            write_float80(lua_tonumber(L, value_index), buffer);
            break;
        case UL_REG_TYPE_INT8_ARRAY_16:
            for (i = 0; i < 16; ++i) {
                lua_geti(L, value_index, i + 1);
                ((int8_t *)buffer)[i] = lua_tointeger(L, -1);
                lua_pop(L, 1);
            }
            break;
        case UL_REG_TYPE_INT16_ARRAY_8:
            for (i = 0; i < 8; ++i) {
                lua_geti(L, value_index, i + 1);
                ((int16_t *)buffer)[i] = lua_tointeger(L, -1);
                lua_pop(L, 1);
            }
            break;
        case UL_REG_TYPE_INT32_ARRAY_4:
            for (i = 0; i < 4; ++i) {
                lua_geti(L, value_index, i + 1);
                ((int32_t *)buffer)[i] = lua_tointeger(L, -1);
                lua_pop(L, 1);
            }
            break;
        case UL_REG_TYPE_INT64_ARRAY_2:
            for (i = 0; i < 2; ++i) {
                lua_geti(L, value_index, i + 1);
                ((int64_t *)buffer)[i] = lua_tointeger(L, -1);
                lua_pop(L, 1);
            }
            break;
        case UL_REG_TYPE_FLOAT32_ARRAY_4:
            for (i = 0; i < 4; ++i) {
                lua_geti(L, value_index, i + 1);
                ((uclua_float32 *)buffer)[i] = lua_tonumber(L, -1);
                lua_pop(L, 1);
            }
            break;
        case UL_REG_TYPE_FLOAT64_ARRAY_2:
            for (i = 0; i < 2; ++i) {
                lua_geti(L, value_index, i + 1);
                ((uclua_float64 *)buffer)[i] = lua_tonumber(L, -1);
                lua_pop(L, 1);
            }
            break;
        case UL_REG_TYPE_INT8_ARRAY_32:
            for (i = 0; i < 32; ++i) {
                lua_geti(L, value_index, i + 1);
                ((int8_t *)buffer)[i] = lua_tointeger(L, -1);
                lua_pop(L, 1);
            }
            break;
        case UL_REG_TYPE_INT16_ARRAY_16:
            for (i = 0; i < 16; ++i) {
                lua_geti(L, value_index, i + 1);
                ((int16_t *)buffer)[i] = lua_tointeger(L, -1);
                lua_pop(L, 1);
            }
            break;
        case UL_REG_TYPE_INT32_ARRAY_8:
            for (i = 0; i < 8; ++i) {
                lua_geti(L, value_index, i + 1);
                ((int32_t *)buffer)[i] = lua_tointeger(L, -1);
                lua_pop(L, 1);
            }
            break;
        case UL_REG_TYPE_INT64_ARRAY_4:
            for (i = 0; i < 4; ++i) {
                lua_geti(L, value_index, i + 1);
                ((int64_t *)buffer)[i] = lua_tointeger(L, -1);
                lua_pop(L, 1);
            }
            break;
        case UL_REG_TYPE_FLOAT32_ARRAY_8:
            for (i = 0; i < 8; ++i) {
                lua_geti(L, value_index, i + 1);
                ((uclua_float32 *)buffer)[i] = lua_tonumber(L, -1);
                lua_pop(L, 1);
            }
            break;
        case UL_REG_TYPE_FLOAT64_ARRAY_4:
            for (i = 0; i < 4; ++i) {
                lua_geti(L, value_index, i + 1);
                ((uclua_float64 *)buffer)[i] = lua_tonumber(L, -1);
                lua_pop(L, 1);
            }
            break;
        case UL_REG_TYPE_INT8_ARRAY_64:
            for (i = 0; i < 64; ++i) {
                lua_geti(L, value_index, i + 1);
                ((int8_t *)buffer)[i] = lua_tointeger(L, -1);
                lua_pop(L, 1);
            }
            break;
        case UL_REG_TYPE_INT32_ARRAY_16:
            for (i = 0; i < 16; ++i) {
                lua_geti(L, value_index, i + 1);
                ((int32_t *)buffer)[i] = lua_tointeger(L, -1);
                lua_pop(L, 1);
            }
            break;
        case UL_REG_TYPE_INT64_ARRAY_8:
            for (i = 0; i < 8; ++i) {
                lua_geti(L, value_index, i + 1);
                ((int64_t *)buffer)[i] = lua_tointeger(L, -1);
                lua_pop(L, 1);
            }
            break;
        case UL_REG_TYPE_FLOAT32_ARRAY_16:
            for (i = 0; i < 16; ++i) {
                lua_geti(L, value_index, i + 1);
                ((uclua_float32 *)buffer)[i] = lua_tonumber(L, -1);
                lua_pop(L, 1);
            }
            break;
        case UL_REG_TYPE_FLOAT64_ARRAY_8:
            for (i = 0; i < 8; ++i) {
                lua_geti(L, value_index, i + 1);
                ((uclua_float64 *)buffer)[i] = lua_tonumber(L, -1);
                lua_pop(L, 1);
            }
            break;

        case UL_REG_TYPE_UNKNOWN:
        default:
            throw LuaBindingError("Invalid register type ID.");
    }

    return Register(buffer, kind);
}


int ul_reg_write(lua_State *L) {
    uc_engine *engine = ul_toengine(L, 1);
    int register_id = luaL_checkinteger(L, 2);
    auto value = static_cast<uint_least64_t>(luaL_checkinteger(L, 3));

    uc_err error = uc_reg_write(engine, register_id, &value);
    if (error != UC_ERR_OK)
        return ul_crash_on_error(L, error);
    return 0;
}


int ul_reg_write_as(lua_State *L) {
    uc_engine *engine = ul_toengine(L, 1);
    int register_id = luaL_checkinteger(L, 2);
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
    int register_id = luaL_checkinteger(L, 2);

    uc_err error = uc_reg_read(engine, register_id, value_buffer);
    if (error != UC_ERR_OK)
        return ul_crash_on_error(L, error);

    lua_pushinteger(L, *reinterpret_cast<lua_Integer *>(value_buffer));
    return 1;
}


int ul_reg_read_as(lua_State *L) {
    uc_engine *engine = ul_toengine(L, 1);
    int register_id = luaL_checkinteger(L, 2);
    auto read_as_type = static_cast<RegisterDataType>(luaL_checkinteger(L, 3));

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
    int n_registers;

    uc_engine *engine = ul_toengine(L, 1);

    /* Second argument will be a table with key-value pairs, the keys being the
     * registers to write to and the values being the values to write to the
     * corresponding registers. */

    /* Count the number of items in the table so we can allocate the buffers of
     * the right size. We can't use luaL_len() because that doesn't tell us how
     * many keys there are in the table, only entries in the array part. */
    lua_pushnil(L);
    for (n_registers = 0; lua_next(L, 2) != 0; ++n_registers)
        lua_pop(L, 1);

    std::unique_ptr<int[]> register_ids(new int[n_registers]);
    std::unique_ptr<int_least64_t[]> values(new int_least64_t[n_registers]);
    std::unique_ptr<void *[]> p_values(new void *[n_registers]);

    /* Iterate through the register/value pairs and put them in the corresponding
     * array positions. */
    lua_pushnil(L);
    for (int i = 0; lua_next(L, 2) != 0; ++i) {
        register_ids[i] = luaL_checkinteger(L, -2);
        values[i] = (lua_Unsigned)luaL_checkinteger(L, -1);
        p_values[i] = &values[i];
        lua_pop(L, 1);
    }

    uc_err error = uc_reg_write_batch(
        engine, register_ids.get(), p_values.get(), n_registers
    );
    if (error != UC_ERR_OK)
        return ul_crash_on_error(L, error);
    return 0;
}


int ul_reg_read_batch(lua_State *L) {
    uc_engine *engine = ul_toengine(L, 1);
    int n_registers = lua_gettop(L) - 1;

    std::unique_ptr<int[]> register_ids(new int[n_registers]);
    std::unique_ptr<register_buffer_type[]> values(new register_buffer_type[n_registers]);
    std::unique_ptr<void *[]> p_values(new void *[n_registers]);

    for (int i = 0; i < n_registers; ++i) {
        register_ids[i] = (int)lua_tointeger(L, i + 2);
        p_values[i] = &values[i];
    }

    memset(values.get(), 0, n_registers * sizeof(register_buffer_type));
    uc_err error = uc_reg_read_batch(
        engine, register_ids.get(), p_values.get(), n_registers
    );
    if (error != UC_ERR_OK)
        return ul_crash_on_error(L, error);

    for (int i = 0; i < n_registers; ++i)
        lua_pushinteger(L, *reinterpret_cast<lua_Integer *>(values[i]));

    return n_registers;
}
