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
#include <errno.h>
#include <inttypes.h>
#include <lua.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
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
    luaL_argcheck(L, engine != NULL, 1, "Engine is null. Was this closed already?");

    uint64_t start = (uint64_t)lua_tointeger(L, 2);
    uint64_t stop = (uint64_t)lua_tointeger(L, 3);
    uint64_t timeout = (uint64_t)lua_tointeger(L, 4);
    size_t n_instructions = (size_t)lua_tointeger(L, 5);

    uc_err error = uc_emu_start(engine, start, stop, timeout, n_instructions);
    ulinternal_crash_if_failed(L, error,
                               "Failed to start emulator with start=0x%08" PRIX64 ", end="
                               "0x%08" PRIX64 ", timeout=%" PRId64 "us (0 = infinity),"
                               " max instructions=%zu (0 = infinity)",
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
                               "Failed to map %zu bytes of memory at address 0x%08" PRIX64
                               ", perm flags=0x%08" PRIX32,
                               length, start, perms);
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
                               "Failed to set memory protections at 0x%08" PRIX64 " for"
                               " %zu bytes with flags=0x%08" PRIX32,
                               start, length, perms);
    return 0;
}

int ul_mem_read(lua_State *L)
{
    uc_engine *engine = (uc_engine *)lua_topointer(L, 1);
    uint64_t address = (uint64_t)lua_tointeger(L, 2);
    size_t size = (size_t)lua_tointeger(L, 3);

    void *buffer = malloc(size);
    if (buffer == NULL)
    {
        ulinternal_crash(L,
                         "Failed to read %zu bytes from address 0x%08" PRIX64 ": buffer"
                         " allocation failed (%d -- %s)",
                         size, address, errno, strerror(errno));
    }

    uc_err error = uc_mem_read(engine, address, buffer, size);
    if (error == UC_ERR_OK)
        lua_pushlstring(L, buffer, size);

    free(buffer);
    ulinternal_crash_if_failed(
        L, error, "Failed to read %zu bytes of memory at address 0x%08" PRIX64, size,
        address);
    return 1;
}

int ul_mem_regions(lua_State *L)
{
    uc_engine *engine = (uc_engine *)lua_topointer(L, 1);

    uc_mem_region *regions;
    uint32_t n_regions;

    uc_err error = uc_mem_regions(engine, &regions, &n_regions);
    ulinternal_crash_if_failed(L, error, "Failed to enumerate mapped memory regions.");

    lua_createtable(L, (int)n_regions, 0);
    for (uint32_t i = 0; i < n_regions; i++)
    {
        lua_pushinteger(L, (int)(i + 1));

        lua_createtable(L, 0, 3);
        lua_pushinteger(L, (lua_Integer)regions[i].begin);
        lua_setfield(L, -2, "begins");

        lua_pushinteger(L, (lua_Integer)regions[i].end);
        lua_setfield(L, -2, "ends");

        lua_pushinteger(L, (lua_Integer)regions[i].perms);
        lua_setfield(L, -2, "perms");

        lua_rawset(L, -3);
    }

    uc_free(regions);
    return 1;
}

int ul_mem_unmap(lua_State *L)
{
    uc_engine *engine = (uc_engine *)lua_topointer(L, 1);
    uint64_t address = (uint64_t)lua_tointeger(L, 2);
    size_t length = (size_t)lua_tointeger(L, 3);

    uc_err error = uc_mem_unmap(engine, address, length);
    ulinternal_crash_if_failed(
        L, error, "Failed to unmap %zu bytes of memory at address 0x%08" PRIX64, length,
        address);
    return 0;
}

int ul_mem_write(lua_State *L)
{
    size_t data_size;

    uc_engine *engine = (uc_engine *)lua_topointer(L, 1);
    uint64_t address = (uint64_t)lua_tointeger(L, 2);
    const void *data = lua_tolstring(L, 3, &data_size);

    uc_err error = uc_mem_write(engine, address, data, data_size);
    ulinternal_crash_if_failed(L, error,
                               "Failed to write %zu bytes to memory at 0x%08" PRIX64,
                               data_size, address);
    return 0;
}
