#include <unicorn/unicorn.h>

#include "unicornlua/context.h"
#include "unicornlua/engine.h"
#include "unicornlua/errors.h"
#include "unicornlua/hooks.h"
#include "unicornlua/lua.h"
#include "unicornlua/memory.h"
#include "unicornlua/registers.h"
#include "unicornlua/utils.h"


const char * const kEngineMetatableName = "unicornlua__engine_meta";
const char * const kEnginePointerMapName = "unicornlua__engine_ptr_map";


// Close the engine only if it hasn't been closed already.
static int maybe_close(lua_State *L) {
    auto engine_object = get_engine_struct(L, 1);
    if (engine_object->engine)
        engine_object->close();
    return 0;
}


const luaL_Reg kEngineMetamethods[] = {
    {"__gc", maybe_close},
    {"__close", maybe_close},
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
    {"reg_read_as", ul_reg_read_as},
    {"reg_read_batch", ul_reg_read_batch},
    {"reg_read_batch_as", ul_reg_read_batch_as},
    {"reg_write", ul_reg_write},
    {"reg_write_as", ul_reg_write_as},
    {"reg_write_batch", ul_reg_write_batch},
    {nullptr, nullptr}
};


UCLuaEngine::UCLuaEngine(lua_State *L, uc_engine *engine) : L(L), engine(engine) {}


UCLuaEngine::~UCLuaEngine() {
    // Only close the engine if it hasn't already been closed. It's perfectly legitimate
    // for the user to close the engine before it gets garbage-collected, so we don't
    // want to crash on garbage collection if they did so.
    if (engine != nullptr)
        close();
}


Hook *UCLuaEngine::create_empty_hook() {
    Hook *hook = new Hook(this->L, this->engine);
    hooks_.insert(hook);
    return hook;
}


void UCLuaEngine::remove_hook(Hook *hook) {
    hooks_.erase(hook);
    delete hook;
}


void UCLuaEngine::start(
    uint64_t start_addr, uint64_t end_addr, uint64_t timeout, size_t n_instructions
) {
    uc_err error = uc_emu_start(engine, start_addr, end_addr, timeout, n_instructions);
    if (error != UC_ERR_OK)
        throw UnicornLibraryError(error);
}


void UCLuaEngine::stop() {
    uc_err error = uc_emu_stop(engine);
    if (error != UC_ERR_OK)
        throw UnicornLibraryError(error);
}


void UCLuaEngine::close() {
    if (engine == nullptr)
        throw LuaBindingError("Attempted to close already-closed engine.");

    for (auto hook : hooks_)
        delete hook;
    hooks_.clear();

    uc_err error = uc_close(engine);
    if (error != UC_ERR_OK)
        throw UnicornLibraryError(error);

    // Signal subsequent calls that this engine is already closed.
    engine = nullptr;
}


size_t UCLuaEngine::query(uc_query_type query_type) const {
    size_t result;
    uc_err error = uc_query(engine, query_type, &result);
    if (error != UC_ERR_OK)
        throw UnicornLibraryError(error);
    return result;
}


uc_err UCLuaEngine::get_errno() const {
    return uc_errno(engine);
}


Context *UCLuaEngine::create_context_in_lua() {
    auto context = (Context *)lua_newuserdata(L, sizeof(Context));
    new (context) Context(*this);

    luaL_setmetatable(L, kContextMetatableName);
    context->update();
    return context;
}


void UCLuaEngine::restore_from_context(Context *context) {
    auto handle = context->get_handle();
    if (handle == nullptr)
        throw LuaBindingError(
            "Attempted to use a context object that has already been freed."
        );

    uc_err error = uc_context_restore(engine, handle);
    if (error != UC_ERR_OK)
        throw UnicornLibraryError(error);
}


void ul_init_engines_lib(lua_State *L) {
    // Create a table with weak values where the engine pointer to engine object
    // mappings will be stored.
    ul_create_weak_table(L, "v");
    lua_setfield(L, LUA_REGISTRYINDEX, kEnginePointerMapName);

    luaL_newmetatable(L, kEngineMetatableName);
    luaL_setfuncs(L, kEngineMetamethods, 0);

    lua_newtable(L);
    luaL_setfuncs(L, kEngineInstanceMethods, 0);
    lua_setfield(L, -2, "__index");

    luaL_newmetatable(L, kContextMetatableName);
    luaL_setfuncs(L, kContextMetamethods, 0);

    lua_newtable(L);
    luaL_setfuncs(L, kContextInstanceMethods, 0);
    lua_setfield(L, -2, "__index");

    lua_pop(L, 2);
}


void ul_get_engine_object(lua_State *L, const uc_engine *engine) {
    lua_getfield(L, LUA_REGISTRYINDEX, kEnginePointerMapName);
    lua_pushlightuserdata(L, (void *)engine);
    lua_gettable(L, -2);

    if (lua_isnil(L, -1)) {
        // Remove nil and engine pointer map at TOS
        lua_pop(L, 2);
        throw LuaBindingError(
            "No engine object is registered for the given pointer. It may have been"
            " deleted already."
        );
    }

    // Remove the engine pointer map from the stack.
    lua_remove(L, -2);
}


int ul_close(lua_State *L) {
    auto engine_object = get_engine_struct(L, 1);
    if (engine_object->engine)
        engine_object->close();

    // Garbage collection should remove the engine object from the pointer map table,
    // but we might as well do it here anyway.
    lua_getfield(L, LUA_REGISTRYINDEX, kEnginePointerMapName);
    lua_pushlightuserdata(L, (void *)engine_object->engine);
    lua_pushnil(L);
    lua_settable(L, -3);
    lua_pop(L, 1);

    return 0;
}


int ul_query(lua_State *L) {
    auto engine_object = get_engine_struct(L, 1);
    auto query_type = static_cast<uc_query_type>(luaL_checkinteger(L, 2));

    size_t result = engine_object->query(query_type);
    lua_pushinteger(L, result);
    return 1;
}


int ul_errno(lua_State *L) {
    auto engine = get_engine_struct(L, 1);
    lua_pushinteger(L, engine->get_errno());
    return 1;
}


int ul_emu_start(lua_State *L) {
    auto engine = get_engine_struct(L, 1);
    auto start = static_cast<uint64_t>(luaL_checkinteger(L, 2));
    auto end = static_cast<uint64_t>(luaL_checkinteger(L, 3));
    auto timeout = static_cast<uint64_t>(luaL_optinteger(L, 4, 0));
    auto n_instructions = static_cast<size_t>(luaL_optinteger(L, 5, 0));

    engine->start(start, end, timeout, n_instructions);
    return 0;
}


int ul_emu_stop(lua_State *L) {
    auto engine = get_engine_struct(L, 1);
    engine->stop();
    return 0;
}


uc_engine *ul_toengine(lua_State *L, int index) {
    auto engine_object = get_engine_struct(L, index);
    if (engine_object->engine == nullptr)
        throw LuaBindingError("Attempted to use closed engine.");

    return engine_object->engine;
}
