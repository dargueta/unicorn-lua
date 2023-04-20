/**
 * Routines and declarations for manipulating Unicorn Lua engine objects.
 *
 * @file engine.h
 */

#pragma once

#include <set>

#include <unicorn/unicorn.h>

#include "unicornlua/hooks.hpp"
#include "unicornlua/lua.hpp"
#include "unicornlua/utils.hpp"

extern const char* const kEngineMetatableName;
extern const char* const kEnginePointerMapName;

struct Context;

class UCLuaEngine {
public:
    UCLuaEngine(lua_State* L, uc_engine* engine);
    ~UCLuaEngine();

    /**
     * Create a @ref Hook object and assign it to this engine, but don't bind it
     * yet.
     *
     * This is useful when creating a hook but not all the pieces have been put
     * together yet. It's used in only one specific case so this function may
     * eventually be removed.
     */
    Hook* create_empty_hook();

    /** Detach and destroy a hook bound to this engine. */
    void remove_hook(Hook* hook);

    /**
     * Create a Context object in memory managed by Lua, and push it on the Lua
     * stack.
     *
     * There's deliberately no way to create a @ref Context *not* in Lua. Unlike
     * hooks, there's no reason to keep a context around once it's no longer
     * used inside Lua. Thus, there isn't really any use in allowing a @ref
     * Context to be created in the heap.
     *
     * Changed in 1.1.0: This now automatically saves the engine state in the
     * context. Before, it was necessary to call `update()` on the returned
     * context object.
     */
    Context* create_context_in_lua();
    void update_context(Context* context) const;
    void restore_from_context(Context* context);
    void free_context(Context* context);

    void start(uint64_t start_addr, uint64_t end_addr, uint64_t timeout = 0,
        size_t n_instructions = 0);
    void stop();
    void close();
    size_t query(uc_query_type query_type) const;
    uc_err get_errno() const;

    uc_engine* get_handle() const noexcept;

private:
    lua_State* L_;
    uc_engine* engine_handle_;
    std::set<Hook*> hooks_;
    std::set<Context*> contexts_;
};

/**
 * Given a `uc_engine` pointer, find the corresponding Lua object and push it.
 *
 * @param L         A pointer to the current Lua state.
 * @param engine    A pointer to the engine we want to get the Lua object for.
 */
void ul_find_lua_engine(lua_State* L, const uc_engine* engine);

/**
 * Initialize the engine object internals, such as registering metatables.
 *
 * This MUST be called before creating any engine objects.
 *
 * @param L         A pointer to the current Lua state.
 */
void ul_init_engines_lib(lua_State* L);

/**
 * Return the value on the stack at @a index as a uc_engine pointer.
 *
 * If the value at @a index is @e not a @ref UCLuaEngine, or the engine has
 * already been closed, a Lua error will be thrown.
 *
 * @param L         A pointer to the current Lua state.
 * @param index     The index on the Lua stack of the value to convert.
 *
 * @return The low-level Unicorn engine.
 */
uc_engine* ul_toengine(lua_State* L, int index);

/**
 * Return the value on the stack at @a index as a pointer to a @ref UCLuaEngine.
 *
 * If the value at @a index is @e not a @ref UCLuaEngine, a Lua error will be
 * thrown.
 *
 * @param L         A pointer to the current Lua state.
 * @param index     The index on the Lua stack of the value to convert.
 *
 * @return The engine.
 */
UCLuaEngine* ul_toluaengine(lua_State* L, int index);

int ul_close(lua_State* L);
int ul_query(lua_State* L);
int ul_errno(lua_State* L);
int ul_emu_start(lua_State* L);
int ul_emu_stop(lua_State* L);
