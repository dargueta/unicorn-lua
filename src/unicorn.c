#include <stdlib.h>

#include <unicorn/unicorn.h>

#include "unicornlua/common.h"
#include "unicornlua/engine.h"
#include "unicornlua/globals.h"
#include "unicornlua/lua.h"
#include "unicornlua/utils.h"


UNICORN_EXPORT int ul_version(lua_State *L) {
    unsigned major, minor;

    uc_version(&major, &minor);

    lua_pushinteger(L, major);
    lua_pushinteger(L, minor);
    return 2;
}


UNICORN_EXPORT int ul_arch_supported(lua_State *L) {
    int architecture = luaL_checkinteger(L, -1);
    lua_pushboolean(L, uc_arch_supported(architecture));
    return 1;
}


UNICORN_EXPORT int ul_open(lua_State *L) {
    int architecture, mode, error_code;
    uc_engine *engine;

    architecture = luaL_checkinteger(L, 1);
    mode = luaL_checkinteger(L, 2);

    error_code = uc_open(architecture, mode, &engine);
    if (error_code != UC_ERR_OK)
        return ul_crash_on_error(L, error_code);

    ul_create_engine_object(L, engine);
    return 1;
}


UNICORN_EXPORT int ul_strerror(lua_State *L) {
    lua_pushstring(L, uc_strerror(luaL_checkinteger(L, 1)));
    return 1;
}


UNICORN_EXPORT int ul_free(lua_State *L) {
    int error = uc_free(*(void **)lua_touserdata(L, 1));

    if (error != UC_ERR_OK)
        return ul_crash_on_error(L, error);
    return 0;
}


static const luaL_Reg kUnicornLibraryFunctions[] = {
    {"arch_supported", ul_arch_supported},
    {"open", ul_open},
    {"strerror", ul_strerror},
    {"version", ul_version},
    {NULL, NULL}
};


static const luaL_Reg kContextMetamethods[] = {
    {"__gc", ul_free},
    {NULL, NULL}
};


UNICORN_EXPORT int luaopen_unicorn__clib(lua_State *L) {
    ul_init_engines_lib(L);

    luaL_newmetatable(L, kContextMetatableName);
    luaL_setfuncs(L, kContextMetamethods, 0);

    luaL_newlib(L, kUnicornLibraryFunctions);
    load_int_constants(L, kGlobalsConstants);
    return 1;
}
