/**
 * Lua bindings for Unicorn context operations.
 *
 * @file context.hpp
 */

#pragma once

#include <unicorn/unicorn.h>

#include "unicornlua/engine.hpp"
#include "unicornlua/lua.hpp"

extern const char* const kContextMetatableName;
extern const luaL_Reg kContextMetamethods[];
extern const luaL_Reg kContextInstanceMethods[];

struct Context {
    uc_context* context_handle;
    UCLuaEngine* engine;
};

int ul_context_save(lua_State* L);
int ul_context_restore(lua_State* L);

/** Deallocate a context object.
 *
 * This function calls `uc_free()` on versions of Unicorn before 1.0.2, and
 * calls `uc_context_free()` on 1.0.2+. In either case, it will behave as
 * expected.
 */
int ul_context_free(lua_State* L);

/**
 * Like @ref ul_context_free, except if the context is closed, it does nothing
 * instead of throwing an exception.
 */
int ul_context_maybe_free(lua_State* L);

Context* ul_toluacontext(lua_State* L, int index);
