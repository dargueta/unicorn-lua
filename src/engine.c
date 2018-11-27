#include <unicorn/unicorn.h>

#include "unicornlua/engine.h"
#include "unicornlua/lua.h"
#include "unicornlua/unicornlua.h"
#include "unicornlua/utils.h"

const char * const kEngineMetatableName = "unicornlua__engine_meta";
const char * const kEnginePointerMapName = "unicornlua__engine_ptr_map";


const luaL_Reg kEngineMetamethods[] = {
    {"__gc", uc_lua__close},
    {NULL, NULL}
};


const luaL_Reg kEngineInstanceMethods[] = {
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


typedef struct {
    uc_engine *engine;
} UCLuaEngine;


void uc_lua__init_engine_lib(lua_State *L) {
    /* Create a table with weak values where the engine pointer to engine object
     * mappings will be stored. */
    uc_lua__create_weak_table(L, "v");
    lua_setfield(L, LUA_REGISTRYINDEX, kEnginePointerMapName);

    luaL_newmetatable(L, kEngineMetatableName);
    luaL_setfuncs(L, kEngineMetamethods, 0);

    lua_newtable(L);
    luaL_setfuncs(L, kEngineInstanceMethods, 0);
    lua_setfield(L, -2, "__index");
}


void uc_lua__create_engine_object(lua_State *L, const uc_engine *engine) {
    UCLuaEngine *engine_object;

    engine_object = lua_newuserdata(L, sizeof(*engine_object));
    engine_object->engine = (uc_engine *)engine;

    luaL_setmetatable(L, kEngineMetatableName);

    /* Add a mapping of the engine pointer to the engine object so that hook
     * callbacks can get the engine object knowing only the pointer. */
    lua_getfield(L, LUA_REGISTRYINDEX, kEnginePointerMapName);
    lua_pushlightuserdata(L, (void *)engine_object->engine);
    lua_pushvalue(L, -2);   /* Duplicate engine object as value */
    lua_settable(L, -3);
    lua_pop(L, 1);      /* Remove pointer map, engine object at TOS again */
}


void uc_lua__free_engine_object(lua_State *L, int index) {
    UCLuaEngine *engine_object;
    int error;

    /* Deliberately not using uc_lua__toengine, see below. */
    engine_object = (UCLuaEngine *)luaL_checkudata(L, index, kEngineMetatableName);

    /* If the engine is already closed, don't try closing it again. Since the
     * engine is automatically closed when it gets garbage collected, if the
     * user manually closes it first this will result in an attempt to close an
     * already-closed engine. */
    if (engine_object->engine == NULL)
        return;

    error = uc_close(engine_object->engine);
    if (error != UC_ERR_OK)
        uc_lua__crash_on_error(L, error);

    /* Clear out the engine pointer so we know it's closed now. */
    engine_object->engine = NULL;
}

/**
 * Given a uc_engine pointer, find the corresponding Lua object and push it.
 *
 * @param L         A pointer to the current Lua state.
 * @param engine    A pointer to the engine we want to get the Lua object for.
 */

void uc_lua__get_engine_object(lua_State *L, const uc_engine *engine) {
    lua_getfield(L, LUA_REGISTRYINDEX, kEnginePointerMapName);

    lua_pushlightuserdata(L, (void *)engine);
    lua_gettable(L, -2);

    if (lua_isnil(L, -1))
        luaL_error(L, "No engine object is registered for pointer %p.", engine);

    /* Remove the engine pointer map from the stack. */
    lua_remove(L, -2);
}


uc_engine *uc_lua__toengine(lua_State *L, int index) {
    UCLuaEngine *engine_object;

    engine_object = (UCLuaEngine *)luaL_checkudata(L, index, kEngineMetatableName);
    if (engine_object->engine == NULL)
        luaL_error(L, "Attempted to use closed engine.");

    return engine_object->engine;
}
