/**
 * @file hooks.h
 */

#ifndef INCLUDE_UNICORNLUA_HOOKS_H_
#define INCLUDE_UNICORNLUA_HOOKS_H_

#include "unicornlua/lua.h"

/**
 * Initialize the hook internals.
 */
void ul_init_hooks_lib(lua_State *L);


int ul_hook_del(lua_State *L);
int ul_hook_add(lua_State *L);

#endif  /* INCLUDE_UNICORNLUA_HOOKS_H_ */
