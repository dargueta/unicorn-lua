/**
 * Compatibility shims for differences between Lua versions
 *
 * @file compat.h
 */

#ifndef INCLUDE_UNICORNLUA_COMPAT_H_
#define INCLUDE_UNICORNLUA_COMPAT_H_

#include "unicornlua/lua.h"

#ifndef LUA_UNSIGNED
    #define LUA_UNSIGNED    unsigned LUA_INTEGER
    typedef LUA_UNSIGNED lua_Unsigned;
#endif


/* Compatibility stuff for Lua < 5.3 */
#if LUA_VERSION_NUM < 503
    LUA_API void lua_seti(lua_State *L, int index, lua_Integer n);
    LUA_API int lua_geti(lua_State *L, int index, lua_Integer i);
#endif


/* Compatibility stuff for Lua < 5.2 */
#if LUA_VERSION_NUM < 502
    LUALIB_API void luaL_setmetatable(lua_State *L, const char *tname);

    /**
     * A partial replacement for Lua 5.2+ @e lua_len.
     *
     * @warning This DOES NOT invoke the __len metamethod, and as of right now
     *          this library doesn't need it so it won't be supported.
     */
    LUA_API void lua_len(lua_State *L, int index);
#endif

#endif  /* INCLUDE_UNICORNLUA_COMPAT_H_ */
