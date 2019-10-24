#include <array>
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


uclua_float80 read_float80(const char *data) {
    uint64_t significand = *reinterpret_cast<const uint64_t *>(data);
    int exponent = *reinterpret_cast<const uint16_t *>(data + 8) & 0x7fff;
    bool sign = (*reinterpret_cast<const uint16_t *>(data + 8) & 0x8000) != 0;

    uclua_float80 signed_significand = significand;
    if (sign)
        signed_significand *= -1;

    if (exponent == 0) {
        if (significand == 0)
            return 0.0;
        return ldexp(signed_significand, exponent - 16382);
    }
    else if (exponent == 0x7fff) {
        switch ((significand & 0xc000000000000000ULL) >> 62) {
            case 0:
                if ((significand & 0x3fffffffffffffffULL) == 0)
                    return sign ? -INFINITY : +INFINITY;
                return NAN;
            case 1:
                return NAN;
            case 2:
                if ((significand & 0x3fffffffffffffffULL) == 0)
                    return sign ? -INFINITY : +INFINITY;
                return NAN;
            case 3:
                return NAN;
            default:
                throw std::logic_error(
                    "BUG: Bit masking on bits 63-62 of float80 significand got an"
                    " unexpected value. This should never happen."
                );
        }
    }

    // Regular number!
    if (significand & 0x8000000000000000ULL)
        return ldexp(signed_significand, exponent - 16383);
    return ldexp(signed_significand, exponent - 16382);
}


void write_float80(uclua_float80 value, char *buffer) {
    int f_type = std::fpclassify(value);
    uint16_t sign_bit = (value < 0) ? 0x8000 : 0;

    switch (f_type) {
        case FP_INFINITE:
            // TODO (dargueta): This won't work on a big-endian machine
            *reinterpret_cast<uint64_t *>(buffer) = 0x8000000000000000;
            *reinterpret_cast<uint16_t *>(buffer + 8) = 0x7fff | sign_bit;
            break;
        case FP_NAN:
            *reinterpret_cast<uint64_t *>(buffer) = 0xffffffffffffffff;
            *reinterpret_cast<uint16_t *>(buffer + 8) = 0xffff;
            break;
        case FP_ZERO:
            *reinterpret_cast<uint64_t *>(buffer) = 0;
            *reinterpret_cast<uint16_t *>(buffer + 8) = 0;
            break;
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


std::array<int8_t, 8> Register::as_8xi8() const { return array_cast<int8_t, 8>(); }
std::array<int16_t, 4> Register::as_4xi16() const { return array_cast<int16_t, 4>(); }
std::array<int32_t, 2> Register::as_2xi32() const { return array_cast<int32_t, 2>(); }
std::array<int64_t, 1> Register::as_1xi64() const { return array_cast<int64_t, 1>(); }
std::array<uclua_float32, 4> Register::as_4xf32() const {
    return array_cast<uclua_float32 , 4>();
}
std::array<uclua_float64, 2> Register::as_2xf64() const {
    return array_cast<uclua_float64 , 2>();
}
std::array<int8_t, 16> Register::as_16xi8() const { return array_cast<int8_t, 16>(); }
std::array<int16_t, 8> Register::as_8xi16() const { return array_cast<int16_t, 8>(); }
std::array<int32_t, 4> Register::as_4xi32() const { return array_cast<int32_t, 4>(); }
std::array<int64_t, 2> Register::as_2xi64() const { return array_cast<int64_t, 2>(); }
std::array<uclua_float32, 8> Register::as_8xf32() const {
    return array_cast<uclua_float32, 8>();
}
std::array<uclua_float64, 4> Register::as_4xf64() const {
    return array_cast<uclua_float64, 4>();
}
std::array<int8_t, 32> Register::as_32xi8() const { return array_cast<int8_t, 32>(); }
std::array<int16_t, 16> Register::as_16xi16() const { return array_cast<int16_t, 16>(); }
std::array<int32_t, 8> Register::as_8xi32() const { return array_cast<int32_t, 8>(); }
std::array<int64_t, 4> Register::as_4xi64() const { return array_cast<int64_t, 4>(); }
std::array<int8_t, 64> Register::as_64xi8() const { return array_cast<int8_t, 64>(); }
std::array<int16_t, 32> Register::as_32xi16() const { return array_cast<int16_t, 32>(); }
std::array<int32_t, 16> Register::as_16xi32() const { return array_cast<int32_t, 16>(); }
std::array<int64_t, 8> Register::as_8xi64() const { return array_cast<int64_t, 8>(); }
std::array<uclua_float64, 8> Register::as_8xf64() const {
    return array_cast<uclua_float64, 8>();
}
std::array<uclua_float32, 16> Register::as_16xf32() const {
    return array_cast<uclua_float32, 16>();
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


int ul_reg_read(lua_State *L) {
    uint_least64_t value = 0;
    uc_engine *engine = ul_toengine(L, 1);
    int register_id = luaL_checkinteger(L, 2);

    uc_err error = uc_reg_read(engine, register_id, &value);
    if (error != UC_ERR_OK)
        return ul_crash_on_error(L, error);

    lua_pushinteger(L, value);
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
    std::unique_ptr<int_least64_t[]> values(new int_least64_t[n_registers]);
    std::unique_ptr<void *[]> p_values(new void *[n_registers]);

    for (int i = 0; i < n_registers; ++i) {
        register_ids[i] = (int)lua_tointeger(L, i + 2);
        p_values[i] = &values[i];
    }

    memset(values.get(), 0, n_registers * sizeof(int_least64_t));
    uc_err error = uc_reg_read_batch(
        engine, register_ids.get(), p_values.get(), n_registers
    );
    if (error != UC_ERR_OK)
        return ul_crash_on_error(L, error);

    for (int i = 0; i < n_registers; ++i)
        lua_pushinteger(L, values[i]);

    return n_registers;
}
