#include <stdlib.h>

#include <unicorn/unicorn.h>

#include "unicornlua/common.h"
#include "unicornlua/engine.h"
#include "unicornlua/lua.h"
#include "unicornlua/unicornlua.h"
#include "unicornlua/utils.h"
#include "unicornlua/constants/arm.h"
#include "unicornlua/constants/arm64.h"
#include "unicornlua/constants/globals.h"
#include "unicornlua/constants/m68k.h"
#include "unicornlua/constants/mips.h"
#include "unicornlua/constants/sparc.h"
#include "unicornlua/constants/x86.h"

const char * const kContextMetatableName = "unicornlua__context_meta";
const char * const kHookMapName = "unicornlua__hook_map";


int uc_lua__version(lua_State *L) {
    unsigned major, minor;

    uc_version(&major, &minor);

    lua_pushinteger(L, major);
    lua_pushinteger(L, minor);
    return 1;
}


int uc_lua__arch_supported(lua_State *L) {
    int architecture = luaL_checkinteger(L, -1);
    lua_pushboolean(L, uc_arch_supported(architecture));
    return 1;
}


int uc_lua__open(lua_State *L) {
    int architecture, mode, error_code;
    uc_engine *engine;

    architecture = luaL_checkinteger(L, 1);
    mode = luaL_checkinteger(L, 2);

    error_code = uc_open(architecture, mode, &engine);
    if (error_code != UC_ERR_OK)
        return uc_lua__crash_on_error(L, error_code);

    uc_lua__create_engine_object(L, engine);
    return 1;
}


int uc_lua__strerror(lua_State *L) {
    lua_pushstring(L, uc_strerror(luaL_checkinteger(L, 1)));
    return 1;
}


int uc_lua__close(lua_State *L) {
    uc_lua__free_engine_object(L, 1);
    return 0;
}


int uc_lua__query(lua_State *L) {
    uc_engine *engine;
    int query_type, error;
    size_t result;

    engine = uc_lua__toengine(L, 1);
    query_type = luaL_checkinteger(L, 1);

    error = uc_query(engine, query_type, &result);
    if (error != UC_ERR_OK)
        return uc_lua__crash_on_error(L, error);

    lua_pushinteger(L, result);
    return 1;
}


int uc_lua__errno(lua_State *L) {
    uc_engine *engine;

    engine = uc_lua__toengine(L, 1);
    lua_pushinteger(L, uc_errno(engine));
    return 1;
}


int uc_lua__emu_start(lua_State *L) {
    uc_engine *engine;
    uint64_t start, end, timeout;
    size_t n_instructions;
    int error;

    engine = uc_lua__toengine(L, 1);
    start = (uint64_t)luaL_checkinteger(L, 2);
    end = (uint64_t)luaL_checkinteger(L, 3);
    timeout = (uint64_t)luaL_optinteger(L, 4, 0);
    n_instructions = (size_t)luaL_optinteger(L, 5, 0);

    error = uc_emu_start(engine, start, end, timeout, n_instructions);
    if (error != UC_ERR_OK)
        return uc_lua__crash_on_error(L, error);
    return 0;
}


int uc_lua__emu_stop(lua_State *L) {
    uc_engine *engine;
    int error;

    engine = uc_lua__toengine(L, 1);

    error = uc_emu_stop(engine);
    if (error != UC_ERR_OK)
        return uc_lua__crash_on_error(L, error);
    return 0;
}


int uc_lua__hook_add(lua_State *L) {
    return luaL_error(L, "Not implemented yet.");
}


int uc_lua__hook_del(lua_State *L) {
    return luaL_error(L, "Not implemented yet.");
}


int uc_lua__free(lua_State *L) {
    int error = uc_free(*(void **)lua_touserdata(L, 1));

    if (error != UC_ERR_OK)
        return uc_lua__crash_on_error(L, error);
    return 0;
}


int uc_lua__context_alloc(lua_State *L) {
    uc_engine *engine;
    uc_context **context;
    int error;

    engine = uc_lua__toengine(L, 1);

    context = (uc_context **)lua_newuserdata(L, sizeof(*context));
    luaL_setmetatable(L, kContextMetatableName);

    error = uc_context_alloc(engine, context);
    if (error != UC_ERR_OK)
        return uc_lua__crash_on_error(L, error);

    return 1;
}


int uc_lua__context_save(lua_State *L) {
    uc_engine *engine;
    uc_context *context;
    int error;

    engine = uc_lua__toengine(L, 1);

    if (lua_gettop(L) < 2)
        /* Caller didn't pass a context to update, so create a new one. */
        uc_lua__context_alloc(L);

    context = uc_lua__tocontext(L, 2);

    error = uc_context_save(engine, context);
    if (error != UC_ERR_OK)
        return uc_lua__crash_on_error(L, error);

    return 1;
}


int uc_lua__context_restore(lua_State *L) {
    uc_engine *engine;
    uc_context *context;
    int error;

    engine = uc_lua__toengine(L, 1);
    context = uc_lua__tocontext(L, 2);

    error = uc_context_restore(engine, context);
    if (error != UC_ERR_OK)
        return uc_lua__crash_on_error(L, error);
    return 0;
}


static const luaL_Reg kUnicornLibraryFunctions[] = {
    {"arch_supported", uc_lua__arch_supported},
    {"open", uc_lua__open},
    {"strerror", uc_lua__strerror},
    {"version", uc_lua__version},
    {NULL, NULL}
};


static const luaL_Reg kContextMetamethods[] = {
    {"__gc", uc_lua__free},
    {NULL, NULL}
};


static int _load_int_constants(lua_State *L, const struct NamedIntConst *constants) {
    int i;

    for (i = 0; constants[i].name != NULL; ++i) {
        /* For some reason I can't get lua_setfield() to work. */
        lua_pushstring(L, constants[i].name);
        lua_pushinteger(L, constants[i].value);
        lua_settable(L, -3);
    }

    return i;
}


int luaopen_unicorn(lua_State *L) {
    uc_lua__init_engine_lib(L);

    /* Create a table with weak keys mapping the engine object to a table with
     * all of its hooks. */
    uc_lua__create_weak_table(L, "k");
    lua_setfield(L, LUA_REGISTRYINDEX, kHookMapName);

    luaL_newmetatable(L, kContextMetatableName);
    luaL_setfuncs(L, kContextMetamethods, 0);

    luaL_newlib(L, kUnicornLibraryFunctions);
    _load_int_constants(L, kGlobalsConstants);
    return 1;
}


int luaopen_unicorn_arm64(lua_State *L) {
    lua_newtable(L);
    _load_int_constants(L, kARM64Constants);
    return 1;
}


int luaopen_unicorn_arm(lua_State *L) {
    lua_newtable(L);
    _load_int_constants(L, kARMConstants);
    return 1;
}


int luaopen_unicorn_m68k(lua_State *L) {
    lua_newtable(L);
    _load_int_constants(L, kM68KConstants);
    return 1;
}


int luaopen_unicorn_mips(lua_State *L) {
    lua_newtable(L);
    _load_int_constants(L, kMIPSConstants);
    return 1;
}


int luaopen_unicorn_sparc(lua_State *L) {
    lua_newtable(L);
    _load_int_constants(L, kSPARCConstants);
    return 1;
}


int luaopen_unicorn_x86(lua_State *L) {
    lua_newtable(L);
    _load_int_constants(L, kX86Constants);
    return 1;
}
