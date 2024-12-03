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
#include <lua.h>
#include <stdarg.h>
#include <stdio.h>

void ulinternal_vsnprintf(lua_State *L, size_t max_size, const char *format, va_list argv)
{
    char *message = malloc(max_size + 1);

    vsnprintf(message, max_size, format, argv);
    message[max_size] = '\0';
    lua_pushstring(L, message);
    free(message);
}

_Noreturn int ulinternal_crash_not_implemented(lua_State *L)
{
    lua_pushstring(L, "BUG: This function isn't implemented in the Lua binding yet.");
    lua_error(L);
    UL_UNREACHABLE_MARKER;
}

void ulinternal_crash_if_failed(lua_State *L, uc_err code, const char *format, ...)
{
    if (code == UC_ERR_OK)
        return;

    luaL_Buffer msgbuf;
    luaL_buffinit(L, &msgbuf);

    // The general form of the produced error message is:
    //      {user message} (Unicorn: error ### -- {unicorn message})

    va_list argv;
    va_start(argv, format);
    ulinternal_vsnprintf(L, UL_MAX_ERROR_MESSAGE_LENGTH, format, argv);
    va_end(argv);

    luaL_addvalue(&msgbuf);

    lua_pushfstring(L, " (Unicorn: error %d -- %s)", (int)code, uc_strerror(code));
    luaL_addvalue(&msgbuf);

    luaL_pushresult(&msgbuf);
    lua_error(L);
    UL_UNREACHABLE_MARKER;
}

_Noreturn int ulinternal_crash_unsupported_operation(lua_State *L)
{
    lua_pushstring(L, "The operation is not supported for this version of Unicorn.");
    lua_error(L);
    UL_UNREACHABLE_MARKER;
}

_Noreturn void ulinternal_crash(lua_State *L, const char *format, ...)
{
    va_list argv;
    va_start(argv, format);
    ulinternal_vsnprintf(L, UL_MAX_ERROR_MESSAGE_LENGTH, format, argv);
    va_end(argv);
    lua_error(L);
    UL_UNREACHABLE_MARKER;
}
