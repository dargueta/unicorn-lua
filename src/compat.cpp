#include "unicornlua/compat.h"
#include "unicornlua/lua.h"


#if LUA_VERSION_NUM < 503

/* WARNING:
 * This backport is (probably) functionally equivalent to the 5.3 behavior but
 * is almost certainly not as fast as the implementation in 5.3.
 */
LUA_API void lua_seti(lua_State *L, int index, lua_Integer n) {
    index = lua_absindex(L, index);

    // Because lua_settable expects the value on top, we need to push the key (n) and
    // then swap the two.
    lua_pushinteger(L, n);  // Push key, stack is [... V K]
    lua_pushvalue(L, -2);   // Push value again, stack is [... V K V]
    lua_remove(L, -3);      // Remove the original value, stack is [... K V]
    lua_settable(L, index);
}


/* Same caveat as above. */
LUA_API int lua_geti(lua_State *L, int index, lua_Integer i) {
    index = lua_absindex(L, index);

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


LUA_API int luaL_len(lua_State *L, int index) {
    int length;
    index = lua_absindex(L, index);

    lua_len(L, index);
    length = lua_tointeger(L, -1);
    lua_pop(L, 1);
    return length;
}


/* Copied and pasted from the Lua 5.3 implementation. */
LUALIB_API void luaL_setfuncs(lua_State *L, const luaL_Reg *l, int nup) {
  luaL_checkstack(L, nup, "too many upvalues");
  for (; l->name != nullptr; l++) {  /* fill the table with given functions */
    int i;
    for (i = 0; i < nup; i++)  /* copy upvalues to the top */
      lua_pushvalue(L, -nup);
    lua_pushcclosure(L, l->func, nup);  /* closure with those upvalues */
    lua_setfield(L, -(nup + 2), l->name);
  }
  lua_pop(L, nup);  /* remove upvalues */
}


LUA_API int lua_absindex(lua_State *L, int index) {
    int top = lua_gettop(L);

    if ((index > 0) || (index <= LUA_REGISTRYINDEX))
        return index;
    return index + top + 1;
}


LUA_API void lua_rawsetp(lua_State *L, int index, const void *p) {
    index = lua_absindex(L, index);

    lua_pushlightuserdata(L, (void *)p);    // Push key, stack is [ ... V K ]
    lua_pushvalue(L, -2);   // Push value, stack is [ ... V K V ]
    lua_rawset(L, index);   // Set table, stack is [ ... V ]
    lua_pop(L, 1);          // Remove extra value, stack is back to how it was.
}

#endif
