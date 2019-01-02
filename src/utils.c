#include <stdlib.h>

#include <unicorn/unicorn.h>

#include "unicornlua/lua.h"

extern const char * const kEngineMetatableName;
extern const char * const kContextMetatableName;
extern const char * const kEnginePointerMapName;


int ul_crash_on_error(lua_State *L, int error) {
    const char *message;

    message = uc_strerror(error);
    lua_pushstring(L, message);
    return lua_error(L);
}


uc_context *ul_tocontext(lua_State *L, int index) {
    uc_context *context;

    context = *(uc_context **)luaL_checkudata(L, index, kContextMetatableName);
    if (context == NULL)
        luaL_error(L, "Attempted to use closed context.");
    return context;
}


void ul_create_weak_table(lua_State *L, const char *mode) {
    lua_newtable(L);
    lua_createtable(L, 0, 1);
    lua_pushstring(L, mode);
    lua_setfield(L, -2, "__mode");
    lua_setmetatable(L, -2);
}


void lua_movetotop(lua_State *L, int index) {
    index = lua_absindex(L, index);
    lua_pushvalue(L, index);
    lua_remove(L, index);
}


int luaL_checkboolean(lua_State *L, int index) {
    luaL_checktype(L, index, LUA_TBOOLEAN);
    return lua_toboolean(L, index);
}


void *luaL_checklightuserdata(lua_State *L, int index) {
    luaL_checktype(L, index, LUA_TLIGHTUSERDATA);
    return lua_touserdata(L, index);
}
