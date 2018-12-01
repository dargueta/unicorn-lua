/**
 * @file hooks.h
 */

#ifndef INCLUDE_UNICORNLUA_HOOKS_H_
#define INCLUDE_UNICORNLUA_HOOKS_H_

#include "unicornlua/lua.h"


/**
 * Create a new, empty hook table for the engine at @a index and attach it.
 *
 * @param L         The current Lua state.
 * @param index     The stack index of the engine object the hook table is for.
 */
void uc_lua__attach_hook_table(lua_State *L, int index);


/**
 * Initialize the hook internals.
 */
void uc_lua__init_hooks_lib(lua_State *L);


int uc_lua__hook_del(lua_State *L);
int uc_lua__hook_add(lua_State *L);

#endif  /* INCLUDE_UNICORNLUA_HOOKS_H_ */
