extern "C" {
#include <lua.h>
}
#include <unicorn/unicorn.h>

#include "unicornlua/engine.h"
#include "unicornlua/hooks.h"
#include "unicornlua/unicornlua.h"
#include "unicornlua/utils.h"

const char * const kContextMetatableName = "unicornlua__context_meta";
const char * const kEngineMetatableName = "unicornlua__engine_meta";
const char * const kEnginePointerMapName = "unicornlua__engine_ptr_map";


const luaL_Reg kEngineMetamethods[] = {
    {"__gc", ul_close},
    {nullptr, nullptr}
};


const luaL_Reg kEngineInstanceMethods[] = {
    {"close", ul_close},
    {"context_restore", ul_context_restore},
    {"context_save", ul_context_save},
    {"emu_start", ul_emu_start},
    {"emu_stop", ul_emu_stop},
    {"errno", ul_errno},
    {"hook_add", ul_hook_add},
    {"hook_del", ul_hook_del},
    {"mem_map", ul_mem_map},
    {"mem_protect", ul_mem_protect},
    {"mem_read", ul_mem_read},
    {"mem_regions", ul_mem_regions},
    {"mem_unmap", ul_mem_unmap},
    {"mem_write", ul_mem_write},
    {"query", ul_query},
    {"reg_read", ul_reg_read},
    {"reg_read_batch", ul_reg_read_batch},
    {"reg_write", ul_reg_write},
    {"reg_write_batch", ul_reg_write_batch},
    {nullptr, nullptr}
};


UCLuaEngine::UCLuaEngine(lua_State *L, uc_engine *engine) : L(L), engine(engine) {}


void UCLuaEngine::add_hook(Hook *hook) {
    hooks.insert(hook);
}


void UCLuaEngine::remove_hook(Hook *hook) {
    hooks.erase(hook);
    delete hook;
}


void UCLuaEngine::close() {
    if (engine == nullptr) {
        luaL_error(L, "Attempted to close already-closed engine: %p", this);
        return;
    }

    // Shared pointers will automatically deallocate the hooks once they're no longer
    // referenced so we don't need to delete these one by one.
    for (auto hook : hooks)
        delete hook;
    hooks.clear();

    uc_err error = uc_close(engine);
    if (error != UC_ERR_OK)
        ul_crash_on_error(L, error);

    // Signal subsequent calls that this engine is already closed.
    engine = nullptr;
}


UCLuaEngine::~UCLuaEngine() {
    // Only close the engine if it hasn't already been closed. It's perfectly legitimate
    // for the user to close the engine before it gets garbage-collected, so we don't
    // want to crash on garbage collection if they did so.
    if (engine != nullptr)
        close();
}


void ul_init_engines_lib(lua_State *L) {
    /* Create a table with weak values where the engine pointer to engine object
     * mappings will be stored. */
    ul_create_weak_table(L, "v");
    lua_setfield(L, LUA_REGISTRYINDEX, kEnginePointerMapName);

    luaL_newmetatable(L, kEngineMetatableName);
    luaL_setfuncs(L, kEngineMetamethods, 0);

    lua_newtable(L);
    luaL_setfuncs(L, kEngineInstanceMethods, 0);
    lua_setfield(L, -2, "__index");

    /* Remove the metatables from the stack. */
    lua_pop(L, 2);
}


void ul_create_engine_object(lua_State *L, uc_engine *engine) {
    // Create a block of memory for the engine userdata and then create the UCLuaEngine
    // in there using "placement new".
    auto udata = lua_newuserdata(L, sizeof(UCLuaEngine));
    new (udata) UCLuaEngine(L, engine);

    luaL_setmetatable(L, kEngineMetatableName);

    /* Add a mapping of the engine pointer to the engine object so that hook
     * callbacks can get the engine object knowing only the pointer. */
    lua_getfield(L, LUA_REGISTRYINDEX, kEnginePointerMapName);
    lua_pushlightuserdata(L, (void *)engine);
    lua_pushvalue(L, -3);   /* Duplicate engine object as value */
    lua_settable(L, -3);
    lua_pop(L, 1);      /* Remove pointer map, engine object at TOS again */
}


void ul_free_engine_object(lua_State *L, int engine_index) {
    engine_index = lua_absindex(L, engine_index);

    /* Deliberately not using ul_toengine, see below. */
    auto engine_object = get_engine_struct(L, engine_index);
    engine_object->close();

    /* Garbage collection should remove the engine object from the pointer map
     * table but it might not be doing it soon enough. */
    lua_getfield(L, LUA_REGISTRYINDEX, kEnginePointerMapName);
    lua_pushlightuserdata(L, (void *)engine_object->engine);
    lua_pushnil(L);
    lua_settable(L, -3);
    lua_pop(L, 1);          /* Remove pointer map */

    /* Clear out the engine pointer so we know it's closed now. */
    engine_object->engine = nullptr;
}


void ul_get_engine_object(lua_State *L, const uc_engine *engine) {
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


int ul_context_alloc(lua_State *L) {
    uc_engine *engine = ul_toengine(L, 1);
    uc_context *context = (uc_context *)lua_newuserdata(L, sizeof(context));
    luaL_setmetatable(L, kContextMetatableName);

    uc_err error = uc_context_alloc(engine, &context);
    if (error != UC_ERR_OK)
        return ul_crash_on_error(L, error);

    return 1;
}


int ul_context_save(lua_State *L) {
    uc_engine *engine = ul_toengine(L, 1);
    if (lua_gettop(L) < 2)
        /* Caller didn't pass a context to update, so create a new one. */
        ul_context_alloc(L);

    uc_context *context = ul_tocontext(L, 2);
    uc_err error = uc_context_save(engine, context);
    if (error != UC_ERR_OK)
        return ul_crash_on_error(L, error);

    return 1;
}


int ul_context_restore(lua_State *L) {
    uc_engine *engine = ul_toengine(L, 1);
    uc_context *context = ul_tocontext(L, 2);

    uc_err error = uc_context_restore(engine, context);
    if (error != UC_ERR_OK)
        return ul_crash_on_error(L, error);
    return 0;
}


int ul_close(lua_State *L) {
    ul_free_engine_object(L, 1);
    return 0;
}


int ul_query(lua_State *L) {
    size_t result;
    uc_engine *engine = ul_toengine(L, 1);
    auto query_type = static_cast<uc_query_type>(luaL_checkinteger(L, 1));

    uc_err error = uc_query(engine, query_type, &result);
    if (error != UC_ERR_OK)
        return ul_crash_on_error(L, error);

    lua_pushinteger(L, result);
    return 1;
}


int ul_errno(lua_State *L) {
    uc_engine *engine = ul_toengine(L, 1);
    lua_pushinteger(L, uc_errno(engine));
    return 1;
}


int ul_emu_start(lua_State *L) {
    uc_engine *engine = ul_toengine(L, 1);
    auto start = static_cast<uint64_t>(luaL_checkinteger(L, 2));
    auto end = static_cast<uint64_t>(luaL_checkinteger(L, 3));
    auto timeout = static_cast<uint64_t>(luaL_optinteger(L, 4, 0));
    auto n_instructions = static_cast<size_t>(luaL_optinteger(L, 5, 0));

    uc_err error = uc_emu_start(engine, start, end, timeout, n_instructions);
    if (error != UC_ERR_OK)
        return ul_crash_on_error(L, error);
    return 0;
}


int ul_emu_stop(lua_State *L) {
    uc_engine *engine = ul_toengine(L, 1);
    uc_err error = uc_emu_stop(engine);

    if (error != UC_ERR_OK)
        return ul_crash_on_error(L, error);
    return 0;
}


uc_engine *ul_toengine(lua_State *L, int index) {
    auto engine_object = get_engine_struct(L, index);
    if (engine_object->engine == nullptr)
        luaL_error(L, "Attempted to use closed engine.");

    return engine_object->engine;
}
