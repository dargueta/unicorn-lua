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

/***
 * `unicorn_c_` is a very very thin wrapper around the C library.
 *
 * Users are discouraged from using it directly, as it makes no provisions for garbage
 * collection or type safety. Instead, use the functions provided by the @{unicorn} module
 * and @{engine.Engine}.
 *
 * @module unicorn_c_
 */

#include "unicornlua/basic_hook_functions.h"
#include "unicornlua/context.h"
#include "unicornlua/control_functions.h"
#include "unicornlua/engine.h"
#include "unicornlua/hooks.h"
#include "unicornlua/registers.h"
#include "unicornlua/utils.h"
#include <lauxlib.h>
#include <lua.h>
#include <stddef.h>
#include <unicorn/unicorn.h>

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
    {"bitwise_and", ul_bitwise_and},
    {"context_save", ul_context_save},
    {"context_save_reuse_existing", ul_context_save_reuse_existing},
    {"context_restore",ul_context_restore},
    {"context_free",ul_context_free},
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
