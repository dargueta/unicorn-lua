/**
 * @file hooks.h
 */

#ifndef INCLUDE_UNICORNLUA_HOOKS_H_
#define INCLUDE_UNICORNLUA_HOOKS_H_

#include "unicornlua/lua.h"

/**
 * Initialize the hook internals.
 */
void uc_lua__init_hooks_lib(lua_State *L);


int uc_lua__hook_del(lua_State *L);
int uc_lua__hook_add(lua_State *L);

#endif  /* INCLUDE_UNICORNLUA_HOOKS_H_ */
