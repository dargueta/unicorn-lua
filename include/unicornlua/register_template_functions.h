#pragma once

#include <array>
#include <cstdint>
#include <cstring>
#include <limits>
#include <sstream>

#include "lua.h"
#include "registers.h"

template <class T, size_t N>
void integer_array_to_table(lua_State* L, const std::array<T, N>& arr)
{
    static_assert(N > 0 && N <= 128, "Array length must be in [1, 128]");
    lua_createtable(L, N, 0);

    for (size_t i = 0; i < N; ++i) {
        lua_pushinteger(L, arr[i]);
        lua_seti(L, -2, static_cast<int>(i) + 1);
    }
}

template <class T, size_t N>
void float_array_to_table(lua_State* L, const std::array<T, N>& arr)
{
    static_assert(N > 0 && N <= 128, "Array length must be in [1, 128]");
    lua_createtable(L, N, 0);

    for (size_t i = 0; i < N; ++i) {
        lua_pushnumber(L, arr[i]);
        lua_seti(L, -2, static_cast<int>(i) + 1);
    }
}

template <class T, int N> std::array<T, N> Register::array_cast() const
{
    std::array<T, N> value {};
    memcpy(value.data(), data_, sizeof(value));
    return value;
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
template <typename T> T try_cast(lua_Integer value)
{
    auto ext_value = static_cast<intmax_t>(value);

    constexpr intmax_t min = std::numeric_limits<T>::min();
    constexpr intmax_t max = std::numeric_limits<T>::max();
    if ((ext_value >= min) && (ext_value <= max))
        return static_cast<T>(value);

    // If we get here then `value` isn't representable as a T.
    auto buf = std::ostringstream();
    buf << "Numeric value out of range: " << value << " is not within [" << min
        << ", " << max << "].";

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
template <typename T>
void write_lua_integer(lua_State* L, int value_index, void* buffer)
{
    lua_Integer lua_int = lua_tointeger(L, value_index);
    T native_value = try_cast<T>(lua_int);
    *reinterpret_cast<T*>(buffer) = native_value;
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
template <typename T>
void write_lua_integer_array(
    lua_State* L, int table_index, int n_elements, void* buffer)
{
    for (int i = 0; i < n_elements; ++i) {
        lua_geti(L, table_index, i + 1);
        write_lua_integer<T>(L, -1, reinterpret_cast<T*>(buffer) + i);
        lua_pop(L, 1);
    }
}
