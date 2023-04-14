/**
 * Lua bindings for Unicorn memory operations.
 *
 * @file memory.h
 */

#pragma once

#include "unicornlua/lua.hpp"

/**
 * Write data to a location in a machine's memory.
 */
int ul_mem_write(lua_State* L);

/**
 * Read data from a location in a machine's memory.
 */
int ul_mem_read(lua_State* L);

int ul_mem_map(lua_State* L);
int ul_mem_unmap(lua_State* L);
int ul_mem_protect(lua_State* L);
int ul_mem_regions(lua_State* L);
