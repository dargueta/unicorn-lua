#include <array>
#include <cstdint>
#include <cstring>
#include <memory>

#include <unicorn/unicorn.h>

#include "unicornlua/compat.h"
#include "unicornlua/engine.h"
#include "unicornlua/lua.h"
#include "unicornlua/registers.h"
#include "unicornlua/utils.h"


template <class T, int N>
std::array<T, N> Register::array_cast() const {
    std::array<T, N> value{};
    memcpy(value.data(), data_, value.size());
    return value;
}


void Register::assign_value(const void *buffer, unsigned n_bytes) {
    if (n_bytes > 64)
        n_bytes = 64;
    memcpy(data_, buffer, n_bytes);
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


//uclua_float80 Register::as_float80() const;
//uclua_float128 Register::as_float128() const;


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
std::array<uclua_float32, 8> Register::as_8xf32() const {
    return array_cast<uclua_float32, 8>();
}
std::array<uclua_float64, 4> Register::as_4xf64() const {
    return array_cast<uclua_float64, 4>();
}
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
    auto value = static_cast<lua_Unsigned>(luaL_checkinteger(L, 3));

    uc_err error = uc_reg_write(engine, register_id, &value);
    if (error != UC_ERR_OK)
        return ul_crash_on_error(L, error);
    return 0;
}


int ul_reg_read(lua_State *L) {
    lua_Unsigned value = 0;
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
    std::unique_ptr<lua_Integer[]> values(new lua_Integer[n_registers]);
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
    std::unique_ptr<lua_Integer[]> values(new lua_Integer[n_registers]);
    std::unique_ptr<void *[]> p_values(new void *[n_registers]);

    for (int i = 0; i < n_registers; ++i) {
        register_ids[i] = (int)lua_tointeger(L, i + 2);
        p_values[i] = &values[i];
    }

    memset(values.get(), 0, n_registers * sizeof(lua_Integer));
    uc_err error = uc_reg_read_batch(
        engine, register_ids.get(), p_values.get(), n_registers
    );
    if (error != UC_ERR_OK)
        return ul_crash_on_error(L, error);

    for (int i = 0; i < n_registers; ++i)
        lua_pushinteger(L, values[i]);

    return n_registers;
}
