#ifndef INCLUDE_UNICORNLUA_NUMBERS_H_
#define INCLUDE_UNICORNLUA_NUMBERS_H_

#include <lua.h>


#if LUA_INT_TYPE == LUA_INT_INT
    #define UC_LUA_STRTOINT         strtol
    #define UC_LUA_STRTOUNSIGNED    strtoul
#elif LUA_INT_TYPE == LUA_INT_LONG
    #define UC_LUA_STRTOINT         strtol
    #define UC_LUA_STRTOUNSIGNED    strtoul
#elif LUA_INT_TYPE == LUA_INT_LONGLONG
    #define UC_LUA_STRTOINT         strtoll
    #define UC_LUA_STRTOUNSIGNED    strtoull
#else
    #error "Unexpected value for LUA_INT_TYPE"
#endif


#if LUA_FLOAT_TYPE == LUA_FLOAT_FLOAT
    #define UC_LUA_STRTOFLOAT   strtof
#elif LUA_FLOAT_TYPE == LUA_FLOAT_DOUBLE
    #define UC_LUA_STRTOFLOAT   strtod
#elif LUA_FLOAT_TYPE == LUA_FLOAT_LONGDOUBLE
    #define UC_LUA_STRTOFLOAT   strtold
#else
    #error "Unexpected value for LUA_FLOAT_TYPE"
#endif


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
lua_Integer uc_lua__cast_integer(lua_State *L, int index);


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
lua_Unsigned uc_lua__cast_unsigned(lua_State *L, int index);

#endif  /* INCLUDE_UNICORNLUA_NUMBERS_H_ */
