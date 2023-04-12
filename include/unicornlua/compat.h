/**
 * Compatibility shims for differences between Lua versions.
 *
 * @file compat.h
 */

#pragma once

extern "C" {
#include <lauxlib.h>
#include <lua.h>
}

/* Compatibility stuff for Lua < 5.3 */
#if LUA_VERSION_NUM < 503
LUA_API void lua_seti(lua_State* L, int index, lua_Integer n);
LUA_API int lua_geti(lua_State* L, int index, lua_Integer i);
#endif

/* Compatibility stuff for Lua < 5.2 */
#if LUA_VERSION_NUM < 502
/* Copied and pasted from the 5.3 implementation. */
LUALIB_API void luaL_setmetatable(lua_State* L, const char* tname);

/**
 * A partial replacement for Lua 5.2+ @e lua_len.
 *
 * @warning This DOES NOT invoke the `__len` metamethod, and as of right now
 *          this library doesn't need it so it won't be supported.
 */
LUA_API void lua_len(lua_State* L, int index);

LUA_API int luaL_len(lua_State* L, int index);

/**
 * Implementation of Lua 5.2+ `lua_absindex`.
 */
LUA_API int lua_absindex(lua_State* L, int index);

/* Copied and pasted from the 5.3 implementation. */
LUALIB_API void luaL_setfuncs(lua_State* L, const luaL_Reg* l, int nup);

LUALIB_API void lua_rawsetp(lua_State* L, int index, const void* p);

#define luaL_newlibtable(L, l) lua_createtable((L), 0, sizeof(l) / sizeof(*(l)))
#define luaL_newlib(L, l)                                                      \
    (luaL_newlibtable((L), (l)), luaL_setfuncs((L), (l), 0))
#endif

// http://lua-users.org/lists/lua-l/2011-11/msg01149.html
#ifndef IS_LUAJIT
#ifdef LUA_JDIR
#define IS_LUAJIT 1
#else
#define IS_LUAJIT 0
#endif
#endif
