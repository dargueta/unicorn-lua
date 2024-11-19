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
 * `unicorn_c_` is a very very thin wrapper around the C library.
 *
 * Users are discouraged from using it directly, as it makes no provisions for garbage
 * collection or type safety. Instead, use the functions provided by the @{unicorn} module
 * and @{engine.Engine}.
 *
 * @module unicorn_c_
 */

#include "unicornlua/control_functions.h"
#include "unicornlua/engine.h"
#include "unicornlua/hooks.h"
#include "unicornlua/registers.h"
#include "unicornlua/utils.h"
#include <lauxlib.h>
#include <lua.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <unicorn/unicorn.h>

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

size_t count_table_elements(lua_State *L, int table_index)
{
    size_t count;

    lua_pushnil(L);
    for (count = 0; lua_next(L, table_index) != 0; ++count)
        lua_pop(L, 1);

#if LUA_VERSION_NUM >= 502
    count += (size_t)luaL_len(L, table_index);
#else
    for (int i = 0;; i++, count++)
    {
        lua_pushinteger(L, i);
        lua_rawget(L, table_index);
        if (lua_isnil(L, -1))
            break;
        lua_pop(L, 1);
    }
    lua_pop(L, 1);
#endif
    return count;
}

/**
 * Open a new Unicorn engine.
 *
 * This is an internal library function. End users should use @{unicorn.open}.
 *
 * @function open
 * @tparam int architecture  The architecture of the engine to create.
 * @tparam int mode_flags  Flags controlling the engine's features and behavior.
 * @treturn userdata  A handle to an open engine.
 */
int ul_open(lua_State *L)
{
    int architecture = lua_tointeger(L, 1);
    int mode_flags = lua_tointeger(L, 2);

    uc_engine *engine;
    uc_err error = uc_open(architecture, mode_flags, &engine);

    ulinternal_crash_if_failed(L, error,
                               "Can't open engine with architecture=%d and flags=0x%08X",
                               architecture, mode_flags);
    lua_pushlightuserdata(L, engine);
    return 1;
}

/**
 * Close an open Unicorn engine.
 *
 * This is an internal library function. End users should use @{engine.Engine:close}.
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

    uc_version(&major, &minor);
    lua_pushinteger(L, (lua_Integer)major);
    lua_pushinteger(L, (lua_Integer)minor);
    return 2;
}

/**
 * Get the message for the given error code, like `strerror` in the C standard library.
 *
 * @tparam int error_code  The error code to get a message for.
 * @treturn string  Unicorn's error message for that error code.
 * @function strerror
 */
int ul_strerror(lua_State *L)
{
    uc_err error_code = (uc_err)lua_tointeger(L, 1);
    lua_pushstring(L, uc_strerror(error_code));
    return 1;
}

static const luaL_Reg kFunctions[] = {
    {"close", ul_close},
    {"create_arm64_sys_hook", ul_create_arm64_sys_hook},
    {"create_code_hook", ul_create_code_hook},
    {"create_cpuid_hook", ul_create_cpuid_hook},
    {"create_generic_no_arguments_hook", ul_create_generic_no_arguments_hook},
    {"create_interrupt_hook", ul_create_interrupt_hook},
    {"create_invalid_mem_access_hook", ul_create_invalid_mem_access_hook},
    {"create_memory_access_hook", ul_create_memory_access_hook},
    {"create_port_in_hook", ul_create_port_in_hook},
    {"create_port_out_hook", ul_create_port_out_hook},
    {"create_edge_generated_hook", ul_create_edge_generated_hook},
    {"create_tcg_opcode_hook", ul_create_tcg_opcode_hook},
    {"emu_start", ul_emu_start},
    {"emu_stop", ul_emu_stop},
    {"errno", ul_errno},
    {"hook_del", ul_hook_del},
    {"mem_map", ul_mem_map},
    {"mem_protect", ul_mem_protect},
    {"mem_read", ul_mem_read},
    {"mem_regions", ul_mem_regions},
    {"mem_unmap", ul_mem_unmap},
    {"mem_write", ul_mem_write},
    {"open", ul_open},
    {"reg_read", ul_reg_read},
    {"reg_read_batch", ul_reg_read_batch},
    {"reg_read_batch_as", ul_reg_read_batch_as},
    {"reg_read_as", ul_reg_read_as},
    {"reg_write", ul_reg_write},
    {"reg_write_batch", ul_reg_write_batch},
    {"reg_write_as", ul_reg_write_as},
    {"strerror", ul_strerror},
    {"version", ul_version},
    {"ctl_exits_disable", ul_ctl_exits_disable},
    {"ctl_exits_enable", ul_ctl_exits_enable},
    {"ctl_flush_tlb", ul_ctl_flush_tlb},
    {"ctl_get_arch", ul_ctl_get_arch},
    {"ctl_get_cpu_model", ul_ctl_get_cpu_model},
    {"ctl_get_exits", ul_ctl_get_exits},
    {"ctl_get_exits_cnt", ul_ctl_get_exits_cnt},
    {"ctl_get_mode", ul_ctl_get_mode},
    {"ctl_get_page_size", ul_ctl_get_page_size},
    {"ctl_get_timeout", ul_ctl_get_timeout},
    {"ctl_remove_cache", ul_ctl_remove_cache},
    {"ctl_request_cache", ul_ctl_request_cache},
    {"ctl_set_cpu_model", ul_ctl_set_cpu_model},
    {"ctl_set_exits", ul_ctl_set_exits},
    {"ctl_set_page_size", ul_ctl_set_page_size},
    {"ulinternal_release_hook_callbacks", ul_release_hook_callbacks},
    {NULL, NULL}};

LUA_API
int luaopen_unicorn_c_(lua_State *L)
{
#if LUA_VERSION_NUM >= 502
    luaL_newlib(L, kFunctions);
#else
    lua_createtable(L, 0, 10);
    luaL_register(L, "unicorn_c_", kFunctions);
#endif
    return 1;
}
