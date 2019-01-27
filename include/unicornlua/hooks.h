/**
 * @file hooks.h
 */

#ifndef INCLUDE_UNICORNLUA_HOOKS_H_
#define INCLUDE_UNICORNLUA_HOOKS_H_

#include "unicornlua/lua.h"


int ul_hook_del(lua_State *L);
int ul_hook_add(lua_State *L);

int ul_hook_del_by_indexes(lua_State *L, int engine_index, int hook_handle_index);

#endif  /* INCLUDE_UNICORNLUA_HOOKS_H_ */
