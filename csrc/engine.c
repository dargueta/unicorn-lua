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
#include <lua.h>
#include <stddef.h>
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
    ulinternal_crash_if_failed(L, error,
                               "Failed to start emulator with start=%#08" PRIX64 ", end="
                               "%08" PRIX64 ", timeout=%" PRId64 "us (0 means none), max"
                               " instructions=%zu (0 means no limit)",
                               start, stop, timeout, n_instructions);

    return 0;
}

int ul_emu_stop(lua_State *L)
{
    uc_engine *engine = (uc_engine *)lua_topointer(L, 1);
    uc_err error = uc_emu_stop(engine);

    ulinternal_crash_if_failed(L, error, "Failed to halt emulation.");
    return 0;
}

int ul_mem_map(lua_State *L)
{
    uc_engine *engine = (uc_engine *)lua_topointer(L, 1);
    uint64_t start = (uint64_t)lua_tointeger(L, 2);
    size_t length = (size_t)lua_tointeger(L, 3);
    uint32_t perms = (uint32_t)lua_tointeger(L, 4);

    uc_err error = uc_mem_map(engine, start, length, perms);
    ulinternal_crash_if_failed(L, error,
                               "Failed to map memory with start=0x%08" PRIX64
                               ", length=%zu bytes, perm flags=0x%08" PRIX32,
                               start, length, perms);

    return 0;
}

int ul_mem_protect(lua_State *L)
{
    uc_engine *engine = (uc_engine *)lua_topointer(L, 1);
    uint64_t start = (uint64_t)lua_tointeger(L, 2);
    size_t length = (size_t)lua_tointeger(L, 3);
    uint32_t perms = (uint32_t)lua_tointeger(L, 4);

    uc_err error = uc_mem_protect(engine, start, length, perms);
    ulinternal_crash_if_failed(L, error,
                               "Failed to set memory protections with start=0x%08" PRIX64
                               ", length=%zu bytes, perm flags=0x%08" PRIX32,
                               start, length, perms);
    return 0;
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
