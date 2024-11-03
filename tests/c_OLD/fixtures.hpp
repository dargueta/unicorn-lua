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

#ifndef INCLUDE_TESTS_C_FIXTURES_H_
#define INCLUDE_TESTS_C_FIXTURES_H_

#include <unicorn/unicorn.h>

#include "unicornlua/engine.hpp"
#include "unicornlua/lua.hpp"

class LuaFixture
{
  public:
    LuaFixture();
    virtual ~LuaFixture();

    lua_State *L;
};

class EngineFixture : public LuaFixture
{
  public:
    EngineFixture();

    UCLuaEngine *uclua_engine;
};

class AutoclosingEngineFixture : public EngineFixture
{
  public:
    ~AutoclosingEngineFixture() override;
};

#endif // INCLUDE_TESTS_C_FIXTURES_H_
