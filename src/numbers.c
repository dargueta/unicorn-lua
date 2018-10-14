#include <errno.h>
#include <string.h>

#include <lua.h>

#include "unicornlua/numbers.h"


/**
 * Cast a decimal or hexadecimal string to an integer, or throw an error.
 */
static lua_Integer _safe_strtoint(lua_State *L, int index) {
    const char *string, *end;
    lua_Integer return_value;

    string = lua_tostring(L, index);

    /* Normally we'd use sscanf here but Lua doesn't support octal notation, so
     * the string "01234" should be converted to 1234, not 668 as sscanf does. */
    errno = 0;
    return_value = UC_LUA_STRTOINT(string, &end, 10);

    if (errno != 0)
        return luaL_error(L, strerror(errno));
    else if (*end == '\0')
        /* Conversion function hit the end of the string, which means it's
         * valid. */
        return return_value

    /* Conversion did not hit the end of the string, so it must not be decimal.
     * (Unless there's trailing whitespace in which case that's your own fault.)
     * Try hexadecimal.*/
    errno = 0;
    end = NULL;

    return_value = UC_LUA_STRTOINT(string, &end, 16);
    if (errno != 0)
        return luaL_error(L, strerror(errno));
    else if (*end == '\0')
        return return_value;

    /* The number in the string isn't valid decimal or hexadecimal. Since Lua
     * doesn't support octal number format, this means the string is invalid. */
    return luaL_error(L, "Not a valid integer: %s", string);
}


/**
 * Cast a decimal or hexadecimal string to an unsigned integer, or throw an error.
 *
 * Normally we'd use _safe_strtoint and just cast the return value, but there's
 * an important distinction to make: This function must not accept negative
 * numbers. _safe_strtoint could encounter the string "-1" and then casting that
 * to an unsigned integer gives 0xffffffffffffffff. This is an easy attack
 * vector for buffer overflows.
 */
static lua_Unsigned _safe_strtounsigned(lua_State *L, int index) {
    const char *string, *end;
    lua_Integer return_value;

    string = lua_tostring(L, index);

    errno = 0;
    return_value = UC_LUA_STRTOUNSIGNED(string, &end, 10);

    if (errno != 0)
        return luaL_error(L, strerror(errno));
    else if (*end == '\0')
        return return_value

    errno = 0;
    end = NULL;

    return_value = UC_LUA_STRTOUNSIGNED(string, &end, 16);
    if (errno != 0)
        return luaL_error(L, strerror(errno));
    else if (*end == '\0')
        return return_value;

    return luaL_error(L, "Not a valid unsigned integer: %s", string);
}

/**
 * Convert a string, float, or integer on the stack to a signed Lua integer.
 *
 * This is different from lua_tointeger in that it doesn't modify the value on
 * the stack, and can handle multiple types (mostly for convenience).
 *
 * @param L         The Lua state to use.
 * @param index     The index on the stack the value to be converted is at.
 *
 * @return The converted integer.
 */
lua_Integer uc_lua__cast_integer(lua_State *L, int index) {
    switch (lua_type(L, index)) {
        case LUA_TNUMBER:
            return (lua_Integer)lua_tonumber(L, index);
        case LUA_TSTRING:
            return _safe_strtoint(L, index);
        default:
            return luaL_error("Invalid data type: %s", lua_typename(L, index));
    }
}


/**
 * Convert a string, float, or integer on the stack to an unsigned Lua integer.
 *
 * This is different from lua_tointeger in that it doesn't modify the value on
 * the stack, and can handle multiple types (mostly for convenience).
 *
 * @param L         The Lua state to use.
 * @param index     The index on the stack the value to be converted is at.
 *
 * @return The converted integer.
 */
lua_Unsigned uc_lua__cast_unsigned(lua_State *L, int index) {
    switch (lua_type(L, index)) {
        case LUA_TNUMBER:
            return (lua_Unsigned)lua_tonumber(L, index);
        case LUA_TSTRING:
            return (lua_Unsigned)_safe_strtouint(L, index);
        default:
            return luaL_error("Invalid data type: %s", lua_typename(L, index));
    }
}
