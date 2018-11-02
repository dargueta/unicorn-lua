/**
 * Compatibility shims for differences between Lua versions
 *
 * @file compat.h
 */

#ifndef INCLUDE_UNICORNLUA_COMPAT_H_
#define INCLUDE_UNICORNLUA_COMPAT_H_

#include "unicornlua/lua.h"


/* Compatibility stuff for Lua < 5.3 */
#if LUA_VERSION_NUM < 503
    LUA_API void lua_seti(lua_State *L, int index, lua_Integer n);
    LUA_API int lua_geti(lua_State *L, int index, lua_Integer i);
#endif


/* Compatibility stuff for Lua < 5.2 */
#if LUA_VERSION_NUM < 502
    #include <stddef.h>

    /* An integer is defined as a ptrdiff_t on Lua 5.1. This is probably the
     * closest thing to an unsigned ptrdiff_t we can get to. */
    typedef size_t lua_Unsigned;

    /* Copied and pasted from the 5.3 implementation. */
    LUALIB_API void luaL_setmetatable(lua_State *L, const char *tname);

    /**
     * A partial replacement for Lua 5.2+ @e lua_len.
     *
     * @warning This DOES NOT invoke the __len metamethod, and as of right now
     *          this library doesn't need it so it won't be supported.
     */
    LUA_API void lua_len(lua_State *L, int index);

    /* Copied and pasted from the 5.3 implementation. */
    LUALIB_API void luaL_setfuncs(lua_State *L, const luaL_Reg *l, int nup);

    #define luaL_newlibtable(L, l)  lua_createtable((L), 0, sizeof(l) / sizeof(*(l)))
    #define luaL_newlib(L, l)       (luaL_newlibtable((L),(l)), luaL_setfuncs((L),(l),0))
#endif

#endif  /* INCLUDE_UNICORNLUA_COMPAT_H_ */