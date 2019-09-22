/**
 * Convenience wrapper for including lua.h and lauxlib.h in C++.
 *
 * This header also defines a few convenience functions that pretend to be part
 * of the Lua C API for the sake of readability. The implementations of functions
 * defined here are in @ref utils.c.
 *
 * @file lua.h
 */

extern "C" {
#include <lauxlib.h>
#include <lua.h>
}

#include "unicornlua/compat.h"

#ifndef lua_swaptoptwo
/**
 * Swap the top two stack items.
 */
#define lua_swaptoptwo(L)   (lua_pushvalue((L), -2), lua_remove((L), -3))
#endif


/**
 * A luaL_check* function for booleans, which normal Lua doesn't provide.
 */
int luaL_checkboolean(lua_State *L, int index);
