/**
 * Convenience wrapper for including lua.h and lauxlib.h in C++.
 *
 * This header also defines a few convenience functions that pretend to be part
 * of the Lua C API for the sake of readability. The implementations of functions
 * defined here are in @ref utils.c.
 *
 * @file lua.h
 */

#ifdef __cplusplus
    extern "C" {
#endif

#include <lauxlib.h>
#include <lua.h>

#ifdef __cplusplus
    }
#endif

#include "unicornlua/compat.h"

#ifndef lua_swaptoptwo
/**
 * Swap the top two stack items.
 */
#define lua_swaptoptwo(L)   (lua_pushvalue((L), -2), lua_remove((L), -3))
#endif

/**
 * Move the item at @a index to the top of the stack.
 *
 * This is somewhat the opposite of lua_insert().
 */
void lua_movetotop(lua_State *L, int index);


/**
 * A luaL_check* function for booleans, which normal Lua doesn't provide.
 */
int luaL_checkboolean(lua_State *L, int index);


/**
 * A luaL_check* function for light userdata, which Lua doesn't provide.
 *
 * This is intended to be like @ref luaL_checkudata but only verifying the type,
 * as light userdata can't have a metatable.
 *
 * @return The light userdata pointer.
 */
void *luaL_checklightuserdata(lua_State *L, int index);
