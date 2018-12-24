#include <assert.h>

#include <unicorn/unicorn.h>

#include "unicornlua/engine.h"
#include "unicornlua/hooks.h"
#include "unicornlua/lua.h"
#include "unicornlua/unicornlua.h"
#include "unicornlua/utils.h"

const char * const kEngineMetatableName = "unicornlua__engine_meta";
const char * const kEnginePointerMapName = "unicornlua__engine_ptr_map";

static int _engine_gc_metamethod(lua_State *L);


const luaL_Reg kEngineMetamethods[] = {
    {"__gc", _engine_gc_metamethod},
    {NULL, NULL}
};


const luaL_Reg kEngineInstanceMethods[] = {
    {"close", _engine_gc_metamethod},
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


static int _engine_gc_metamethod(lua_State *L) {
    uc_lua__free_engine_object(L, 1);
    return 0;
}


void uc_lua__init_engines_lib(lua_State *L) {
    /* Create a table with weak values where the engine pointer to engine object
     * mappings will be stored. */
    uc_lua__create_weak_table(L, "v");
    lua_setfield(L, LUA_REGISTRYINDEX, kEnginePointerMapName);

    luaL_newmetatable(L, kEngineMetatableName);
    luaL_setfuncs(L, kEngineMetamethods, 0);

    lua_newtable(L);
    luaL_setfuncs(L, kEngineInstanceMethods, 0);
    lua_setfield(L, -2, "__index");

    /* Remove the metatables from the stack. */
    lua_pop(L, 2);
}


void uc_lua__create_engine_object(lua_State *L, const uc_engine *engine) {
    UCLuaEngine *engine_object;

    engine_object = lua_newuserdata(L, sizeof(*engine_object));
    engine_object->engine = (uc_engine *)engine;

    luaL_setmetatable(L, kEngineMetatableName);

    /* Add a mapping of the engine pointer to the engine object so that hook
     * callbacks can get the engine object knowing only the pointer. */
    lua_getfield(L, LUA_REGISTRYINDEX, kEnginePointerMapName);
    lua_pushlightuserdata(L, (void *)engine);
    lua_pushvalue(L, -3);   /* Duplicate engine object as value */
    lua_settable(L, -3);
    lua_pop(L, 1);      /* Remove pointer map, engine object at TOS again */

    lua_newtable(L);
    engine_object->hook_table_ref = luaL_ref(L, LUA_REGISTRYINDEX);
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

    /* Garbage collection should remove the engine object from the pointer map
     * table but it might not be doing it soon enough. */
    lua_getfield(L, LUA_REGISTRYINDEX, kEnginePointerMapName);
    lua_pushlightuserdata(L, (void *)engine_object->engine);
    lua_pushnil(L);
    lua_settable(L, -3);
    lua_pop(L, 1);          /* Remove pointer map */

    /* Free the hook table. TODO: Release the hooks. */
    luaL_unref(L, LUA_REGISTRYINDEX, engine_object->hook_table_ref);
    engine_object->hook_table_ref = LUA_NOREF;

    /* Clear out the engine pointer so we know it's closed now. */
    engine_object->engine = NULL;
}


void uc_lua__get_engine_object(lua_State *L, const uc_engine *engine) {
    lua_getfield(L, LUA_REGISTRYINDEX, kEnginePointerMapName);
    lua_pushlightuserdata(L, (void *)engine);
    lua_gettable(L, -2);

    if (lua_isnil(L, -1)) {
        /* Remove nil and engine pointer map at TOS */
        lua_pop(L, 2);
        luaL_error(L, "No engine object is registered for pointer %p.", engine);
    }

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
