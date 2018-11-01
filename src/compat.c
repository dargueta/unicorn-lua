#include "unicornlua/compat.h"
#include "unicornlua/lua.h"


#if LUA_VERSION_NUM < 503

/* WARNING:
 * This backport is (probably) functionally equivalent to the 5.3 behavior but
 * is almost certainly not as fast as the implementation in 5.3.
 */
LUA_API void lua_seti(lua_State *L, int index, lua_Integer n) {
    /* Because lua_settable expects the value on top, we need to push the
     * key (n) and then swap the two. */
    lua_pushinteger(L, n);
    lua_insert(L, lua_gettop(L) - 1);
    lua_settable(L, index);
}


/* Same caveat as above. */
LUA_API int lua_geti(lua_State *L, int index, lua_Integer i) {
    lua_pushinteger(L, i);
    lua_gettable(L, index);
    return lua_type(L, -1);
}

#endif


/* Compatibility stuff for Lua < 5.2 */
#if LUA_VERSION_NUM < 502

/* This is an exact copy of the 5.3 implementation. */
LUALIB_API void luaL_setmetatable(lua_State *L, const char *tname) {
    luaL_getmetatable(L, tname);
    lua_setmetatable(L, -2);
}


LUA_API void lua_len(lua_State *L, int index) {
    lua_pushinteger(L, (lua_Integer)lua_objlen(L, index));
}

#endif
