#include <stdlib.h>

#include <unicorn/unicorn.h>

#include "unicornlua/common.h"
#include "unicornlua/engine.h"
#include "unicornlua/globals.h"
#include "unicornlua/hooks.h"
#include "unicornlua/lua.h"
#include "unicornlua/unicornlua.h"
#include "unicornlua/utils.h"

const char * const kContextMetatableName = "unicornlua__context_meta";


int ul_version(lua_State *L) {
    unsigned major, minor;

    uc_version(&major, &minor);

    lua_pushinteger(L, major);
    lua_pushinteger(L, minor);
    return 2;
}


int ul_arch_supported(lua_State *L) {
    int architecture = luaL_checkinteger(L, -1);
    lua_pushboolean(L, uc_arch_supported(architecture));
    return 1;
}


int ul_open(lua_State *L) {
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


int ul_strerror(lua_State *L) {
    lua_pushstring(L, uc_strerror(luaL_checkinteger(L, 1)));
    return 1;
}


int ul_close(lua_State *L) {
    ul_free_engine_object(L, 1);
    return 0;
}


int ul_query(lua_State *L) {
    uc_engine *engine;
    int query_type, error;
    size_t result;

    engine = ul_toengine(L, 1);
    query_type = luaL_checkinteger(L, 1);

    error = uc_query(engine, query_type, &result);
    if (error != UC_ERR_OK)
        return ul_crash_on_error(L, error);

    lua_pushinteger(L, result);
    return 1;
}


int ul_errno(lua_State *L) {
    uc_engine *engine;

    engine = ul_toengine(L, 1);
    lua_pushinteger(L, uc_errno(engine));
    return 1;
}


int ul_emu_start(lua_State *L) {
    uc_engine *engine;
    uint64_t start, end, timeout;
    size_t n_instructions;
    int error;

    engine = ul_toengine(L, 1);
    start = (uint64_t)luaL_checkinteger(L, 2);
    end = (uint64_t)luaL_checkinteger(L, 3);
    timeout = (uint64_t)luaL_optinteger(L, 4, 0);
    n_instructions = (size_t)luaL_optinteger(L, 5, 0);

    error = uc_emu_start(engine, start, end, timeout, n_instructions);
    if (error != UC_ERR_OK)
        return ul_crash_on_error(L, error);
    return 0;
}


int ul_emu_stop(lua_State *L) {
    uc_engine *engine;
    int error;

    engine = ul_toengine(L, 1);

    error = uc_emu_stop(engine);
    if (error != UC_ERR_OK)
        return ul_crash_on_error(L, error);
    return 0;
}


int ul_free(lua_State *L) {
    int error = uc_free(*(void **)lua_touserdata(L, 1));

    if (error != UC_ERR_OK)
        return ul_crash_on_error(L, error);
    return 0;
}


int ul_context_alloc(lua_State *L) {
    uc_engine *engine;
    uc_context *context;
    int error;

    engine = ul_toengine(L, 1);

    context = (uc_context *)lua_newuserdata(L, sizeof(context));
    luaL_setmetatable(L, kContextMetatableName);

    error = uc_context_alloc(engine, &context);
    if (error != UC_ERR_OK)
        return ul_crash_on_error(L, error);

    return 1;
}


int ul_context_save(lua_State *L) {
    uc_engine *engine;
    uc_context *context;
    int error;

    engine = ul_toengine(L, 1);

    if (lua_gettop(L) < 2)
        /* Caller didn't pass a context to update, so create a new one. */
        ul_context_alloc(L);

    context = ul_tocontext(L, 2);

    error = uc_context_save(engine, context);
    if (error != UC_ERR_OK)
        return ul_crash_on_error(L, error);

    return 1;
}


int ul_context_restore(lua_State *L) {
    uc_engine *engine;
    uc_context *context;
    int error;

    engine = ul_toengine(L, 1);
    context = ul_tocontext(L, 2);

    error = uc_context_restore(engine, context);
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


int luaopen_unicorn__clib(lua_State *L) {
    ul_init_engines_lib(L);

    luaL_newmetatable(L, kContextMetatableName);
    luaL_setfuncs(L, kContextMetamethods, 0);

    luaL_newlib(L, kUnicornLibraryFunctions);
    load_int_constants(L, kGlobalsConstants);
    return 1;
}
