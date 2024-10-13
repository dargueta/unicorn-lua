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
 * Lua bindings for Unicorn context operations.
 *
 * @file context.hpp
 */

#pragma once

#include <unicorn/unicorn.h>

#include "unicornlua/engine.hpp"
#include "unicornlua/lua.hpp"

extern const char *const kContextMetatableName;
extern const luaL_Reg kContextMetamethods[];
extern const luaL_Reg kContextInstanceMethods[];

struct Context
{
    uc_context *context_handle;
    UCLuaEngine *engine;
};

int ul_context_save(lua_State *L);
int ul_context_restore(lua_State *L);

/** Deallocate a context object.
 *
 * This function calls `uc_free()` on versions of Unicorn before 1.0.2, and
 * calls `uc_context_free()` on 1.0.2+. In either case, it will behave as
 * expected.
 */
int ul_context_free(lua_State *L);

/**
 * Like @ref ul_context_free, except if the context is closed, it does nothing
 * instead of throwing an exception.
 */
int ul_context_maybe_free(lua_State *L);

Context *ul_toluacontext(lua_State *L, int index);
