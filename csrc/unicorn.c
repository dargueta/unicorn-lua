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

/// @module unicorn_c_

#include <lauxlib.h>
#include <lua.h>
#include <unicorn/unicorn.h>

void ulinternal_crash_if_failed(lua_State *L, uc_err code, const char *context)
{
    if (code == UC_ERR_OK)
        return;

    const char *message = uc_strerror(code);
    luaL_error(L, "[error %d] %s: %s", code, context, message);
}

/**
 * Open a new Unicorn engine.
 *
 * @tparam int architecture  The architecture of the engine to create.
 * @tparam int mode_flags  Flags controlling the engine's features and behavior.
 * @treturn userdata  A handle to an open engine.
 * @function open
 */
int ul_open(lua_State *L)
{
    int architecture = lua_tointeger(L, 1);
    int mode_flags = lua_tointeger(L, 2);

    uc_engine *engine;
    uc_err error = uc_open(architecture, mode_flags, &engine);
    ulinternal_crash_if_failed(L, error, "Failed to open engine");

    lua_pushlightuserdata(L, engine);
    return 1;
}

/**
 * Close an open Unicorn engine.
 *
 * @tparam userdata engine  A handle to an open engine.
 * @function close
 */
int ul_close(lua_State *L)
{
    uc_engine *engine = (uc_engine *)lua_topointer(L, 1);

    uc_err error = uc_close(engine);
    ulinternal_crash_if_failed(L, error, "Failed to close engine");
    return 0;
}

/**
 * Get the version of the Unicorn C library (not this Lua binding).
 *
 * @treturn {int,int}  The major and minor versions of the library, respectively.
 * @function version
 */
int ul_version(lua_State *L)
{
    unsigned major, minor;
    uc_err error = uc_version(&major, &minor);

    ulinternal_crash_if_failed(L, error, "Failed to get Unicorn library version");
    lua_pushinteger(L, (lua_Integer)major);
    lua_pushinteger(L, (lua_Integer)minor);
    return 2;
}

static const luaL_Reg kFunctions[] = {
    {"open", ul_open}, {"close", ul_close}, {"version", ul_version}, {NULL, NULL}};

UNICORN_EXPORT
int luaopen_unicorn_c_(lua_State *L)
{
    lua_createtable(L, 0, 4);
    luaL_setfuncs(L, kFunctions, 0);
    return 1;
}
