// Copyright (C) 2017-2024 by Diego Argueta
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

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
int ul_mem_write(lua_State *L);

/**
 * Read data from a location in a machine's memory.
 */
int ul_mem_read(lua_State *L);

int ul_mem_map(lua_State *L);
int ul_mem_unmap(lua_State *L);
int ul_mem_protect(lua_State *L);
int ul_mem_regions(lua_State *L);
