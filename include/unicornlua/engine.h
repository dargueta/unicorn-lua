/**
 * Routines and declarations for manipulating Unicorn Lua engine objects.
 *
 * @file engine.h
 */

#ifndef INCLUDE_UNICORNLUA_ENGINE_H_
#define INCLUDE_UNICORNLUA_ENGINE_H_

#include <set>

#include <unicorn/unicorn.h>

#include "unicornlua/hooks.h"
#include "unicornlua/lua.h"

extern const char * const kEngineMetatableName;
extern const char * const kEnginePointerMapName;
extern const luaL_Reg kEngineInstanceMethods[];
extern const luaL_Reg kEngineMetamethods[];


class Context;


class UCLuaEngine {
public:
    UCLuaEngine(lua_State *L, uc_engine *engine);
    ~UCLuaEngine();

    /**
     * Create a @ref Hook object and assign it to this engine, but don't bind it yet.
     *
     * This is useful when creating a hook but not all the pieces have been put together
     * yet. It's used in only one specific case so this function will eventually be
     * removed.
     *
     * @deprecated
     */
    Hook *create_empty_hook();

    /**
     * Create a fully initialized @ref Hook and assign it to this engine.
     *
     * @param hook_handle   The handle for this hook as returned by the Unicorn library.
     * @param callback_func_ref
     *     A reference in the C registry to a Lua function that serves as the callback
     *     to execute when the hook is triggered.
     * @param user_data_ref
     *     Optional. A reference in the C registry to a Lua object that'll be passed to
     *     the hook callback on every invocation. If not given, ``nil`` will be used.
     *
     * @return The initialized @ref Hook.
     */
    Hook *create_hook(
        uc_hook hook_handle, int callback_func_ref, int user_data_ref=LUA_REFNIL
    );

    /** Detach and destroy a hook bound to this engine. */
    void remove_hook(Hook *hook);

    /**
     * Create a Context object in memory managed by Lua, and push it on the Lua stack.
     *
     * There's deliberately no way to create a @ref Context *not* in Lua. Unlike hooks,
     * there's no reason to keep a context around once it's no longer used inside Lua.
     * Thus, there isn't really any use in allowing a @ref Context to be created in the
     * heap.
     */
    Context *create_context_in_lua();
    void restore_from_context(Context *context);

    void start(
        uint64_t start_addr, uint64_t end_addr, uint64_t timeout=0,
        size_t n_instructions=0
    );
    void stop();
    void close();
    size_t query(uc_query_type query_type) const;
    uc_err get_errno() const;

    lua_State *L;
    uc_engine *engine;

private:
    std::set<Hook *> hooks_;
};


/**
 * Given a `uc_engine` pointer, find the corresponding Lua object and push it.
 *
 * @param L         A pointer to the current Lua state.
 * @param engine    A pointer to the engine we want to get the Lua object for.
 */
void ul_get_engine_object(lua_State *L, const uc_engine *engine);


/**
 * Initialize the engine object internals, such as registering metatables.
 *
 * This MUST be called before creating any engine objects.
 *
 * @param L         A pointer to the current Lua state.
 */
void ul_init_engines_lib(lua_State *L);


/**
 * Return the value on the stack at @a index as a uc_engine pointer.
 *
 * If the value at @a index is @e not a @ref UCLuaEngine, or the engine has already been
 * closed, a Lua error will be thrown.
 *
 * @param L         A pointer to the current Lua state.
 * @param index     The index on the Lua stack of the value to convert.
 *
 * @return The engine.
 */
uc_engine *ul_toengine(lua_State *L, int index);


#define get_engine_struct(L, index)   \
    reinterpret_cast<UCLuaEngine *>(luaL_checkudata((L), (index), kEngineMetatableName))


int ul_close(lua_State *L);
int ul_query(lua_State *L);
int ul_errno(lua_State *L);
int ul_emu_start(lua_State *L);
int ul_emu_stop(lua_State *L);
uc_engine *ul_toengine(lua_State *L, int index);

#endif  /* INCLUDE_UNICORNLUA_ENGINE_H_ */
