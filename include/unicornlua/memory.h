/**
 * Lua bindings for Unicorn memory operations.
 *
 * @file memory.h
 */

#ifndef INCLUDE_UNICORNLUA_MEMORY_H_
#define INCLUDE_UNICORNLUA_MEMORY_H_

#include <lua.h>

/**
 * Write data to a location in a machine's memory.
 */
int uc_lua__mem_write(lua_State *L, int index);


/**
 * Read data from a location in a machine's memory.
 */
int uc_lua__mem_read(lua_State *L, int index);


int uc_lua__mem_map(lua_State *L, int index);
int uc_lua__mem_unmap(lua_State *L, int index);
int uc_lua__mem_protect(lua_State *L, int index);
int uc_lua__mem_regions(lua_State *L, int index);

#endif  /* INCLUDE_UNICORNLUA_MEMORY_H_ */
