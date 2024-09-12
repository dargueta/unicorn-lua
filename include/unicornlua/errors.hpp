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
 * Exceptions for the Lua bindings for the Unicorn CPU emulator.
 *
 * @file errors.h
 */

#pragma once

#include <stdexcept>

#include <unicorn/unicorn.h>

#include "unicornlua/lua.hpp"

/**
 * Exception class for translating Unicorn error codes into C++ exceptions.
 */
class UnicornLibraryError : public std::runtime_error
{
  public:
    explicit UnicornLibraryError(uc_err error);

    /** Return the Unicorn error code that triggered this exception. */
    uc_err get_error() const noexcept;
    void rethrow_as_lua_error(lua_State *L);

  private:
    uc_err error_;
};

/**
 * Base class for exceptions thrown due to an error in the Lua binding.
 *
 * Unlike @ref UnicornLibraryError, these exceptions are never thrown when a
 * library operation fails. Rather, this exception is used when something goes
 * wrong with the glue code, such as when Lua passes the wrong kind of argument
 * to a function.
 */
class LuaBindingError : public std::runtime_error
{
  public:
    explicit LuaBindingError(const char *message);
    void rethrow_as_lua_error(lua_State *L);
};
