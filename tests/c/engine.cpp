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

#include "doctest.h"
#include "fixtures.hpp"
#include "unicornlua/context.hpp"
#include "unicornlua/errors.hpp"
#include "unicornlua/lua.hpp"

TEST_CASE_FIXTURE(EngineFixture, "UCLuaEngine::close() sets engine handle to null")
{
    uclua_engine->close();
    CHECK_MESSAGE(uclua_engine->get_handle() == nullptr,
                  "Engine handle should be null after closing.");
}

TEST_CASE_FIXTURE(EngineFixture, "UCLuaEngine::close() crashes if you call it twice")
{
    uclua_engine->close();
    CHECK_MESSAGE(uclua_engine->get_handle() == nullptr,
                  "Engine handle should be null after closing.");
    CHECK_THROWS_AS(uclua_engine->close(), LuaBindingError);
}

TEST_CASE_FIXTURE(AutoclosingEngineFixture, "UCLuaEngine::query() generally works")
{
    CHECK_EQ(uclua_engine->query(UC_QUERY_PAGE_SIZE), 4096);
}

TEST_CASE_FIXTURE(AutoclosingEngineFixture,
                  "UCLuaEngine::query() raises exception when given a bad query type")
{
    CHECK_THROWS_AS(uclua_engine->query((uc_query_type)-123), UnicornLibraryError);
}

TEST_CASE_FIXTURE(AutoclosingEngineFixture, "errno() on clean engine works")
{
    // We haven't done anything with the engine so its status should be fine.
    CHECK_EQ(uclua_engine->get_errno(), UC_ERR_OK);
}

// TODO (dargueta): Force the engine into a bad state to verify ::get_errno()
