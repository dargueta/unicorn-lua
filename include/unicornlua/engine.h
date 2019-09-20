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

    Hook *create_empty_hook();
    Hook *create_hook(
        uc_hook hook_handle, int callback_func_ref, int user_data_ref
    );
    void remove_hook(Hook *hook);

    Context *create_context();
    void restore_from_context(Context *context);
    void remove_context(Context *context);

    void close();

    lua_State *L;
    uc_engine *engine;

private:
    std::set<Hook *> hooks;
    std::set<Context *> contexts;
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
 * If the value at @a index is @e not a uc_engine struct, or the engine has
 * already been closed, a Lua error will be thrown.
 *
 * @param L         A pointer to the current Lua state.
 * @param index     The index on the Lua stack of the value to convert.
 *
 * @return The engine.
 */
uc_engine *ul_toengine(lua_State *L, int index);


#define get_engine_struct(L, index)   \
    reinterpret_cast<UCLuaEngine *>(luaL_checkudata((L), (index), kEngineMetatableName))

#endif  /* INCLUDE_UNICORNLUA_ENGINE_H_ */
