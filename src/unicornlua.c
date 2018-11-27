#include <stdlib.h>

#include <unicorn/unicorn.h>

#include "unicornlua/common.h"
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

const char * const kEngineMetatableName = "unicornlua__engine_meta";
const char * const kContextMetatableName = "unicornlua__context_meta";
const char * const kEnginePointerMapName = "unicornlua__engine_ptr_map";
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
    uc_engine **engine;

    architecture = luaL_checkinteger(L, 1);
    mode = luaL_checkinteger(L, 2);

    /* Need to create regular userdata because light userdata can't have a
     * metatable. */
    engine = lua_newuserdata(L, sizeof(*engine));

    error_code = uc_open(architecture, mode, engine);
    if (error_code != UC_ERR_OK)
        return uc_lua__crash_on_error(L, error_code);

    luaL_setmetatable(L, kEngineMetatableName);

    /* Add a mapping of the engine pointer to the engine object so that hook
     * callbacks can get the engine object knowing only the pointer. */
    lua_getfield(L, LUA_REGISTRYINDEX, kEnginePointerMapName);
    lua_pushlightuserdata(L, *engine);
    lua_pushvalue(L, -2);   /* Duplicate engine object as value */
    lua_settable(L, -3);
    lua_pop(L, 1);      /* Remove pointer map, engine object at TOS again */

    /* Create an entry in the registry for this engine, and have it point to a
     * table that will be used to hold the engine's hooks. */
    lua_pushlightuserdata(L, *engine);
    lua_newtable(L);
    lua_settable(L, LUA_REGISTRYINDEX);

    return 1;
}


int uc_lua__strerror(lua_State *L) {
    lua_pushstring(L, uc_strerror(luaL_checkinteger(L, 1)));
    return 1;
}


int uc_lua__close(lua_State *L) {
    uc_engine **engine;
    uc_hook hook;
    int error;

    /* Deliberately not using uc_lua__toengine, see below. */
    engine = (uc_engine **)luaL_checkudata(L, 1, kEngineMetatableName);

    /* If the engine is already closed, don't try closing it again. Since the
     * engine is automatically closed when it gets garbage collected, if the
     * user manually closes it first this will result in an attempt to close an
     * already-closed engine.
     */
    if (*engine == NULL)
        return 0;

    /* When we created this engine, we associated a table with it in the Lua
     * registry to hold its associated hooks. Remove all hooks and delete that
     * table from the registry. */
    lua_pushlightuserdata(L, *engine);
    lua_gettable(L, LUA_REGISTRYINDEX);

    /* The table holding the hooks is at the top of the stack now. Iterate
     * through it and release each hook individually. */
    lua_pushnil(L);
    while (lua_next(L, -2) != 0) {
        /* The key is the hook, value is a Lua function. Once we delete the
         * hook table the functions will be garbage collected if possible. */
        hook = (uc_hook)lua_tointeger(L, -2);
        error = uc_hook_del(*engine, hook);
        if (error)
            return uc_lua__crash_on_error(L, error);

        /* Pop the value off, keeping the hook ID for the next iteration. */
        lua_pop(L, 1);
    }

    /* All hooks removed. Delete the table to release the hook callbacks. */
    lua_pushlightuserdata(L, *engine);
    lua_pushnil(L);
    lua_settable(L, LUA_REGISTRYINDEX);

    error = uc_close(*engine);
    if (error != UC_ERR_OK)
        return uc_lua__crash_on_error(L, error);

    /* Clear out the engine pointer so we know it's closed now. */
    *engine = NULL;
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


static const luaL_Reg kEngineMetamethods[] = {
    {"__gc", uc_lua__close},
    {NULL, NULL}
};

static const luaL_Reg kEngineInstanceMethods[] = {
    {"close", uc_lua__close},
    {"context_restore", uc_lua__context_restore},
    {"context_save", uc_lua__context_save},
    {"emu_start", uc_lua__emu_start},
    {"emu_stop", uc_lua__emu_stop},
    {"errno", uc_lua__errno},
    {"hook_add", uc_lua__hook_add},
    {"hook_del", uc_lua__hook_del},
    {"mem_map", uc_lua__mem_map},
    {"mem_protect", uc_lua__mem_protect},
    {"mem_read", uc_lua__mem_read},
    {"mem_regions", uc_lua__mem_regions},
    {"mem_unmap", uc_lua__mem_unmap},
    {"mem_write", uc_lua__mem_write},
    {"query", uc_lua__query},
    {"reg_read", uc_lua__reg_read},
    {"reg_read_batch", uc_lua__reg_read_batch},
    {"reg_write", uc_lua__reg_write},
    {"reg_write_batch", uc_lua__reg_write_batch},
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
    /* Create a table with weak values where the engine pointer to engine object
     * mappings will be stored. */
    uc_lua__create_weak_table(L, "v");
    lua_setfield(L, LUA_REGISTRYINDEX, kEnginePointerMapName);

    /* Create a table with weak keys mapping the engine object to a table with
     * all of its hooks. */
    uc_lua__create_weak_table(L, "k");
    lua_setfield(L, LUA_REGISTRYINDEX, kHookMapName);

    luaL_newmetatable(L, kEngineMetatableName);
    luaL_setfuncs(L, kEngineMetamethods, 0);

    lua_newtable(L);
    luaL_setfuncs(L, kEngineInstanceMethods, 0);
    lua_setfield(L, -2, "__index");

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
