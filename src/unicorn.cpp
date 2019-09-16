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
    auto architecture = static_cast<uc_arch>(luaL_checkinteger(L, -1));
    lua_pushboolean(L, uc_arch_supported(architecture));
    return 1;
}


UNICORN_EXPORT int ul_open(lua_State *L) {
    auto architecture = static_cast<uc_arch>(luaL_checkinteger(L, 1));
    auto mode = static_cast<uc_mode>(luaL_checkinteger(L, 2));

    uc_engine *engine;
    uc_err error = uc_open(architecture, mode, &engine);
    if (error != UC_ERR_OK)
        return ul_crash_on_error(L, error);

    ul_create_engine_object(L, engine);
    return 1;
}


UNICORN_EXPORT int ul_strerror(lua_State *L) {
    auto error = static_cast<uc_err>(luaL_checkinteger(L, 1));
    lua_pushstring(L, uc_strerror(error));
    return 1;
}


UNICORN_EXPORT int ul_free(lua_State *L) {
    uc_err error = uc_free(*(void **)lua_touserdata(L, 1));
    if (error != UC_ERR_OK)
        return ul_crash_on_error(L, error);
    return 0;
}


static const luaL_Reg kUnicornLibraryFunctions[] = {
    {"arch_supported", ul_arch_supported},
    {"open", ul_open},
    {"strerror", ul_strerror},
    {"version", ul_version},
    {nullptr, nullptr}
};


static const luaL_Reg kContextMetamethods[] = {
    {"__gc", ul_free},
    {nullptr, nullptr}
};


UNICORN_EXPORT int luaopen_unicorn__clib(lua_State *L) {
    ul_init_engines_lib(L);

    luaL_newmetatable(L, kContextMetatableName);
    luaL_setfuncs(L, kContextMetamethods, 0);

    luaL_newlib(L, kUnicornLibraryFunctions);
    load_int_constants(L, kGlobalsConstants);
    return 1;
}
