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

#include <cerrno>
#include <sstream>

#include <unicorn/unicorn.h>

#include "doctest.h"
#include "fixtures.hpp"
#include "unicornlua/engine.hpp"
#include "unicornlua/lua.hpp"

LuaFixture::LuaFixture()
{
    errno = 0;
    L = luaL_newstate();
    REQUIRE_EQ(errno, 0);
    REQUIRE_NE(L, nullptr);
}

LuaFixture::~LuaFixture()
{
    // The test may close the state for us in a couple cases where we
    // deliberately trigger a panic, since the state is no longer valid.
    if (L == nullptr)
        return;

    if (lua_gettop(L) > 0)
    {
        std::ostringstream buf;
        buf << "Garbage left on the stack after test exited:\n";
        for (int i = 1; i <= lua_gettop(L); ++i)
        {
            const char *type_name = lua_typename(L, i);
            buf << "At stack index " << i << ": " << type_name << "\n";
        }
        FAIL(buf.str());
    }
    lua_close(L);
}

EngineFixture::EngineFixture() : LuaFixture(), uclua_engine(nullptr)
{
    ul_init_engines_lib(L);
    CHECK_MESSAGE(lua_gettop(L) == 0,
                  "Garbage left on the stack after initializing the engine system.");

    uc_engine *engine_handle;
    uc_err error = uc_open(UC_ARCH_X86, UC_MODE_32, &engine_handle);
    REQUIRE_MESSAGE(error == UC_ERR_OK, "Failed to create an x86-32 engine.");

    uclua_engine = new UCLuaEngine(L, engine_handle);
    CHECK_NE(uclua_engine->get_handle(), nullptr);
    CHECK_MESSAGE(lua_gettop(L) == 0,
                  "Garbage on the stack after creating the engine object.");
}

AutoclosingEngineFixture::~AutoclosingEngineFixture()
{
    // This REQUIRE shouldn't be necessary but we're getting segfaults in LuaJIT
    // but only on OSX. I'm at my wits' end trying to figure this out.
    REQUIRE(L != nullptr);
    CHECK_MESSAGE(lua_gettop(L) == 0,
                  "Trash on the stack just BEFORE deleting the engine C++ object");
    delete uclua_engine;
    CHECK_MESSAGE(lua_gettop(L) == 0,
                  "Trash on the stack AFTER deleting the engine C++ object.");
}
