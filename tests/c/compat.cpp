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

#include <cstring>
#include <iostream>

#include "doctest.h"
#include "fixtures.hpp"
#include "unicornlua/compat.hpp"
#include "unicornlua/lua.hpp"

TEST_CASE_FIXTURE(LuaFixture, "[5.3 compat] lua_seti() basic")
{
    lua_newtable(L);
    lua_pushliteral(L, "This is a string.");
    REQUIRE_EQ(lua_gettop(L), 2);

    lua_seti(L, 1, 5);

    CHECK_EQ(lua_gettop(L), 1);             // Only the table should be on the stack.
    REQUIRE_EQ(lua_type(L, 1), LUA_TTABLE); // Verify it's a table

    // Retrieve whatever it is at index 5
    lua_pushinteger(L, 5);
    lua_rawget(L, 1);

    // Should be a string...
    CHECK_EQ(lua_type(L, -1), LUA_TSTRING);
    const char *result = lua_tostring(L, -1);
    CHECK_EQ(strcmp(result, "This is a string."), 0);

    // Remove the string and table
    REQUIRE_GE(lua_gettop(L), 2);
    lua_pop(L, 2);
}

TEST_CASE_FIXTURE(LuaFixture, "[5.3 compat] lua_geti() basic")
{
    lua_newtable(L);
    lua_pushinteger(L, 1);
    lua_pushinteger(L, 1234567890);

    REQUIRE_EQ(lua_gettop(L), 3);

    // Don't use lua_seti because it crashes on OSX + LuaJIT.
    lua_rawset(L, 1);

    CHECK_EQ(lua_gettop(L), 1);           // Only the table should be on the stack.
    CHECK_EQ(lua_type(L, 1), LUA_TTABLE); // Verify it's a table

    // Retrieve whatever it is at index 1
    lua_geti(L, 1, 1);

    // Should be an integer...
    CHECK_EQ(lua_type(L, -1), LUA_TNUMBER);
    CHECK_EQ(lua_tointeger(L, -1), 1234567890);

    // Remove the int and table
    lua_pop(L, 2);
}

// TODO (dargueta): Make tests where there's already stuff on the stack.
