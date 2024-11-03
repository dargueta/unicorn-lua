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

#include "unicornlua/utils.h"
#include <inttypes.h>
#include <lauxlib.h>
#include <lua.h>
#include <stdint.h>
#include <unicorn/unicorn.h>

int ul_errno(lua_State *L)
{
    uc_engine *engine = (uc_engine *)lua_topointer(L, 1);
    lua_pushinteger(L, uc_errno(engine));
    return 1;
}

int ul_emu_start(lua_State *L)
{
    uc_engine *engine = (uc_engine *)lua_topointer(L, 1);
    uint64_t start = (uint64_t)lua_tointeger(L, 2);
    uint64_t stop = (uint64_t)lua_tointeger(L, 3);
    uint64_t timeout = (uint64_t)lua_tointeger(L, 4);
    size_t n_instructions = (size_t)lua_tointeger(L, 5);

    uc_err error = uc_emu_start(engine, start, stop, timeout, n_instructions);
    if (error != UC_ERR_OK)
    {
        luaL_error(L,
                   "[error %d] Failed to start emulator with start=%#08" PRIX64
                   ", end=%08" PRIX64 ", timeout=" PRId64
                   "us (0=none), max instructions=%z"
                   " (0=no limit): %s",
                   start, stop, timeout, n_instructions, uc_strerror(error));
        UL_UNREACHABLE_MARKER;
    }

    return 0;
}

int ul_emu_stop(lua_State *L)
{
    ulinternal_crash_not_implemented(L);
}

int ul_mem_map(lua_State *L)
{
    ulinternal_crash_not_implemented(L);
}

int ul_mem_protect(lua_State *L)
{
    ulinternal_crash_not_implemented(L);
}

int ul_mem_read(lua_State *L)
{
    ulinternal_crash_not_implemented(L);
}

int ul_mem_regions(lua_State *L)
{
    ulinternal_crash_not_implemented(L);
}

int ul_mem_unmap(lua_State *L)
{
    ulinternal_crash_not_implemented(L);
}
