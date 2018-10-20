/**
 * Lua bindings for Unicorn register operations.
 *
 * @file registers.h
 */

#ifndef INCLUDE_UNICORNLUA_REGISTERS_H_
#define INCLUDE_UNICORNLUA_REGISTERS_H_

#include <lua.h>

int uc_lua__reg_write(lua_State *L);
int uc_lua__reg_read(lua_State *L);
int uc_lua__reg_write_batch(lua_State *L);
int uc_lua__reg_read_batch(lua_State *L);

#endif  /* INCLUDE_UNICORNLUA_REGISTERS_H_ */
