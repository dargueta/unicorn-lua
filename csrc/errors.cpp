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

#include <stdexcept>

#include <unicorn/unicorn.h>

#include "unicornlua/errors.hpp"
#include "unicornlua/lua.hpp"

UnicornLibraryError::UnicornLibraryError(uc_err error)
    : std::runtime_error(uc_strerror(error)), error_(error)
{
}

uc_err UnicornLibraryError::get_error() const noexcept
{
    return error_;
}

void UnicornLibraryError::rethrow_as_lua_error(lua_State *L)
{
    luaL_error(L, what());
}

LuaBindingError::LuaBindingError(const char *message) : std::runtime_error(message)
{
}

void LuaBindingError::rethrow_as_lua_error(lua_State *L)
{
    luaL_error(L, what());
}
