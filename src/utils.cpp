#include <unicorn/unicorn.h>

#include "unicornlua/lua.h"
#include "unicornlua/utils.h"


int ul_crash_on_error(lua_State *L, uc_err error) {
    const char *message = uc_strerror(error);
    lua_pushstring(L, message);
    return lua_error(L);
}


void ul_create_weak_table(lua_State *L, const char *mode) {
    lua_newtable(L);
    lua_createtable(L, 0, 1);
    lua_pushstring(L, mode);
    lua_setfield(L, -2, "__mode");
    lua_setmetatable(L, -2);
}


void load_int_constants(lua_State *L, const struct NamedIntConst *constants) {
    for (int i = 0; constants[i].name != nullptr; ++i) {
        lua_pushinteger(L, constants[i].value);
        lua_setfield(L, -2, constants[i].name);
    }
}
