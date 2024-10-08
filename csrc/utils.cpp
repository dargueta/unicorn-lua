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

#include <unicorn/unicorn.h>

#include "unicornlua/lua.hpp"
#include "unicornlua/utils.hpp"

void ul_crash_on_error(lua_State *L, uc_err error)
{
    const char *message = uc_strerror(error);
    lua_checkstack(L, 1);
    lua_pushstring(L, message);
    lua_error(L);
    UL_UNREACHABLE_MARKER;
}

void ul_create_weak_table(lua_State *L, const char *mode)
{
    lua_newtable(L);
    lua_createtable(L, 0, 1);
    lua_pushstring(L, mode);
    lua_setfield(L, -2, "__mode");
    lua_setmetatable(L, -2);
}

void load_int_constants(lua_State *L, const struct NamedIntConst *constants)
{
    for (int i = 0; constants[i].name != nullptr; ++i)
    {
        lua_pushinteger(L, constants[i].value);
        lua_setfield(L, -2, constants[i].name);
    }
}

size_t count_table_elements(lua_State *L, int table_index)
{
    size_t count = 0;

    lua_pushnil(L);
    for (count = 0; lua_next(L, table_index) != 0; ++count)
        lua_pop(L, 1);
    return count;
}
