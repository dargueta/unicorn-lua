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

#include "unicornlua/hooks.hpp"
#include "doctest.h"
#include "fixtures.hpp"
#include "unicornlua/lua.hpp"

TEST_CASE_FIXTURE(AutoclosingEngineFixture, "Empty Hook created as expected")
{
    Hook *hook = uclua_engine->create_empty_hook();

    CHECK_MESSAGE(hook->get_callback() == LUA_NOREF,
                  "Hook callback should be undefined.");
    CHECK_MESSAGE(hook->get_user_data() == LUA_REFNIL,
                  "User data bound to hook should be nil by default.");
    CHECK_MESSAGE(hook->get_hook_handle() == 0, "Hook handle should be 0 by default.");
}
