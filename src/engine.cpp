#include <unicorn/unicorn.h>

#include "unicornlua/context.hpp"
#include "unicornlua/control_functions.hpp"
#include "unicornlua/engine.hpp"
#include "unicornlua/errors.hpp"
#include "unicornlua/hooks.hpp"
#include "unicornlua/lua.hpp"
#include "unicornlua/memory.hpp"
#include "unicornlua/registers.hpp"
#include "unicornlua/unicornlua.hpp"
#include "unicornlua/utils.hpp"

const char* const kEngineMetatableName = "unicornlua__engine_meta";
const char* const kEnginePointerMapName = "unicornlua__engine_ptr_map";

// Close the engine only if it hasn't been closed already.
static int maybe_close(lua_State* L)
{
    UCLuaEngine* engine_object = ul_toluaengine(L, 1);
    uc_engine* engine_handle = engine_object->get_handle();

    if (engine_handle != nullptr)
        engine_object->close();
    return 0;
}

static constexpr luaL_Reg kEngineMetamethods[] = { { "__gc", maybe_close },
    { "__close", maybe_close }, { nullptr, nullptr } };

static constexpr luaL_Reg kEngineInstanceMethods[] = { { "close", ul_close },
    { "context_restore", ul_context_restore },
    { "context_save", ul_context_save },
    { "ctl_exits_disable", ul_ctl_exits_disable },
    { "ctl_exits_enable", ul_ctl_exits_enable },
    { "ctl_flush_tlb", ul_ctl_flush_tlb }, { "ctl_get_arch", ul_ctl_get_arch },
    { "ctl_get_cpu_model", ul_ctl_get_cpu_model },
    { "ctl_get_exits", ul_ctl_get_exits },
    { "ctl_get_exits_cnt", ul_ctl_get_exits_cnt },
    { "ctl_get_mode", ul_ctl_get_mode },
    { "ctl_get_page_size", ul_ctl_get_page_size },
    { "ctl_get_timeout", ul_ctl_get_timeout },
    { "ctl_remove_cache", ul_ctl_remove_cache },
    { "ctl_request_cache", ul_ctl_request_cache },
    { "ctl_set_cpu_model", ul_ctl_set_cpu_model },
    { "ctl_set_exits", ul_ctl_set_exits },
    { "ctl_set_page_size", ul_ctl_set_page_size },
    { "emu_start", ul_emu_start }, { "emu_stop", ul_emu_stop },
    { "errno", ul_errno }, { "hook_add", ul_hook_add },
    { "hook_del", ul_hook_del }, { "mem_map", ul_mem_map },
    { "mem_protect", ul_mem_protect },
    // n.b. mem_map_ptr() is irrelevant for Lua
    { "mem_read", ul_mem_read }, { "mem_regions", ul_mem_regions },
    { "mem_unmap", ul_mem_unmap }, { "mem_write", ul_mem_write },
    { "query", ul_query }, { "reg_read", ul_reg_read },
    { "reg_read_as", ul_reg_read_as }, { "reg_read_batch", ul_reg_read_batch },
    { "reg_read_batch_as", ul_reg_read_batch_as },
    { "reg_write", ul_reg_write }, { "reg_write_as", ul_reg_write_as },
    { "reg_write_batch", ul_reg_write_batch }, { nullptr, nullptr } };

UCLuaEngine* ul_toluaengine(lua_State* L, int index)
{
    return reinterpret_cast<UCLuaEngine*>(
        luaL_checkudata(L, index, kEngineMetatableName));
}

UCLuaEngine::UCLuaEngine(lua_State* L, uc_engine* engine)
    : L_(L)
    , engine_handle_(engine)
{
}

UCLuaEngine::~UCLuaEngine()
{
    // Only close the engine if it hasn't already been closed. It's perfectly
    // legitimate for the user to close the engine before it gets
    // garbage-collected, so we don't want to crash on garbage collection if
    // they did so.
    if (engine_handle_ != nullptr)
        close();
}

Hook* UCLuaEngine::create_empty_hook()
{
    Hook* hook = new Hook(L_, engine_handle_);
    hooks_.insert(hook);
    return hook;
}

void UCLuaEngine::remove_hook(Hook* hook)
{
    hooks_.erase(hook);
    delete hook;
}

void UCLuaEngine::start(uint64_t start_addr, uint64_t end_addr,
    uint64_t timeout, size_t n_instructions)
{
    uc_err error = uc_emu_start(
        engine_handle_, start_addr, end_addr, timeout, n_instructions);
    if (error != UC_ERR_OK)
        throw UnicornLibraryError(error);
}

void UCLuaEngine::stop()
{
    uc_err error = uc_emu_stop(engine_handle_);
    if (error != UC_ERR_OK)
        throw UnicornLibraryError(error);
}

void UCLuaEngine::close()
{
    if (engine_handle_ == nullptr)
        throw LuaBindingError("Attempted to close already-closed engine.");

    for (auto hook : hooks_)
        delete hook;
    hooks_.clear();

    while (!contexts_.empty()) {
        auto context = *contexts_.begin();
        free_context(context);
    }

    uc_err error = uc_close(engine_handle_);
    if (error != UC_ERR_OK)
        throw UnicornLibraryError(error);

    // Signal subsequent calls that this engine is already closed.
    engine_handle_ = nullptr;
}

size_t UCLuaEngine::query(uc_query_type query_type) const
{
    size_t result;
    uc_err error = uc_query(engine_handle_, query_type, &result);
    if (error != UC_ERR_OK)
        throw UnicornLibraryError(error);
    return result;
}

uc_err UCLuaEngine::get_errno() const { return uc_errno(engine_handle_); }

Context* UCLuaEngine::create_context_in_lua()
{
    // The userdata we pass back to Lua is just a pointer to the context we
    // created on the normal heap. We can't use a light userdata because light
    // userdata can't have metatables.
    auto context
        = reinterpret_cast<Context*>(lua_newuserdata(L_, sizeof(Context)));
    if (context == nullptr)
        throw std::bad_alloc();

    // We now have an initialized a Lua userdata on the stack that we're going
    // to return to the calling function. We need to set the metatable on it
    // first.
    luaL_setmetatable(L_, kContextMetatableName);

    context->context_handle = nullptr;
    context->engine = this;

    // Save the engine's state
    update_context(context);
    contexts_.insert(context);
    return context;
}

void UCLuaEngine::restore_from_context(Context* context)
{
    if (context->context_handle == nullptr)
        throw LuaBindingError(
            "Attempted to use a context object that has already been freed.");
    if (contexts_.find(context) == contexts_.end())
        throw LuaBindingError(
            "Tried to restore engine from a context it doesn't own.");

    uc_err error = uc_context_restore(engine_handle_, context->context_handle);
    if (error != UC_ERR_OK)
        throw UnicornLibraryError(error);
}

void UCLuaEngine::update_context(Context* context) const
{
    uc_err error;

    if (context->context_handle == nullptr) {
        error = uc_context_alloc(engine_handle_, &context->context_handle);
        if (error != UC_ERR_OK)
            throw UnicornLibraryError(error);
    }

    error = uc_context_save(engine_handle_, context->context_handle);
    if (error != UC_ERR_OK)
        throw UnicornLibraryError(error);
}

void UCLuaEngine::free_context(Context* context)
{
    if (context->context_handle == nullptr)
        throw LuaBindingError("Attempted to remove a context object that has "
                              "already been freed.");
    if (contexts_.find(context) == contexts_.end())
        throw LuaBindingError(
            "Attempted to free a context object from the wrong engine.");

    uc_err error;

#if UNICORNLUA_UNICORN_MAJOR_MINOR_PATCH >= MAKE_VERSION(1, 0, 2)
    /* Unicorn 1.0.2 added its own separate function for freeing contexts. */
    error = uc_context_free(context->context_handle);
#else
    /* Unicorn 1.0.1 and lower uses uc_free(). */
    error = uc_free(context->context_handle);
#endif

    contexts_.erase(context);
    context->context_handle = nullptr;
    context->engine = nullptr;
    if (error != UC_ERR_OK)
        throw UnicornLibraryError(error);
}

uc_engine* UCLuaEngine::get_handle() const noexcept { return engine_handle_; }

void ul_init_engines_lib(lua_State* L)
{
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

void ul_find_lua_engine(lua_State* L, const uc_engine* engine)
{
    lua_getfield(L, LUA_REGISTRYINDEX, kEnginePointerMapName);
    lua_pushlightuserdata(L, (void*)engine);
    lua_gettable(L, -2);

    if (lua_isnil(L, -1)) {
        // Remove nil and engine pointer map at TOS
        lua_pop(L, 2);
        throw LuaBindingError("No engine object is registered for the given "
                              "pointer. It may have been deleted already.");
    }

    // Remove the engine pointer map from the stack.
    lua_remove(L, -2);
}

int ul_close(lua_State* L)
{
    UCLuaEngine* engine_object = ul_toluaengine(L, 1);
    uc_engine* engine_handle = engine_object->get_handle();

    if (engine_handle == nullptr)
        return 0;

    // Garbage collection should remove the engine object from the pointer map
    // table, but we might as well do it here anyway.
    lua_getfield(L, LUA_REGISTRYINDEX, kEnginePointerMapName);
    lua_pushlightuserdata(L, (void*)engine_handle);
    lua_pushnil(L);
    lua_settable(L, -3);
    lua_pop(L, 1);

    // Free the actual engine object.
    engine_object->close();
    return 0;
}

int ul_query(lua_State* L)
{
    const UCLuaEngine* engine_object = ul_toluaengine(L, 1);
    auto query_type = static_cast<uc_query_type>(luaL_checkinteger(L, 2));

    size_t result = engine_object->query(query_type);
    lua_pushinteger(L, static_cast<lua_Integer>(result));
    return 1;
}

int ul_errno(lua_State* L)
{
    const UCLuaEngine* engine = ul_toluaengine(L, 1);
    lua_pushinteger(L, engine->get_errno());
    return 1;
}

int ul_emu_start(lua_State* L)
{
    UCLuaEngine* engine = ul_toluaengine(L, 1);
    auto start = static_cast<uint64_t>(luaL_checkinteger(L, 2));
    auto end = static_cast<uint64_t>(luaL_checkinteger(L, 3));
    auto timeout = static_cast<uint64_t>(luaL_optinteger(L, 4, 0));
    auto n_instructions = static_cast<size_t>(luaL_optinteger(L, 5, 0));

    engine->start(start, end, timeout, n_instructions);
    return 0;
}

int ul_emu_stop(lua_State* L)
{
    UCLuaEngine* engine = ul_toluaengine(L, 1);
    engine->stop();
    return 0;
}

uc_engine* ul_toengine(lua_State* L, int index)
{
    const UCLuaEngine* engine_object = ul_toluaengine(L, index);
    uc_engine* engine_handle = engine_object->get_handle();

    if (engine_handle == nullptr)
        throw LuaBindingError("Attempted to use closed engine.");

    return engine_handle;
}
