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

#pragma once

#include "utils.h"
#include <lua.h>
#include <unicorn/unicorn.h>

#if UC_API_MAJOR >= 2
int ul_ctl_exits_disable(lua_State *L);
int ul_ctl_exits_enable(lua_State *L);
int ul_ctl_flush_tlb(lua_State *L);
int ul_ctl_get_arch(lua_State *L);
int ul_ctl_get_cpu_model(lua_State *L);
int ul_ctl_get_exits(lua_State *L);
int ul_ctl_get_exits_cnt(lua_State *L);
int ul_ctl_get_mode(lua_State *L);
int ul_ctl_get_page_size(lua_State *L);
int ul_ctl_get_timeout(lua_State *L);
int ul_ctl_remove_cache(lua_State *L);
int ul_ctl_request_cache(lua_State *L);
int ul_ctl_set_cpu_model(lua_State *L);
int ul_ctl_set_exits(lua_State *L);
int ul_ctl_set_page_size(lua_State *L);
#else
#    define ul_ctl_exits_disable ulinternal_crash_unsupported_operation
#    define ul_ctl_exits_enable ulinternal_crash_unsupported_operation
#    define ul_ctl_flush_tlb ulinternal_crash_unsupported_operation
#    define ul_ctl_get_arch ulinternal_crash_unsupported_operation
#    define ul_ctl_get_cpu_model ulinternal_crash_unsupported_operation
#    define ul_ctl_get_exits ulinternal_crash_unsupported_operation
#    define ul_ctl_get_exits_cnt ulinternal_crash_unsupported_operation
#    define ul_ctl_get_mode ulinternal_crash_unsupported_operation
#    define ul_ctl_get_page_size ulinternal_crash_unsupported_operation
#    define ul_ctl_get_timeout ulinternal_crash_unsupported_operation
#    define ul_ctl_remove_cache ulinternal_crash_unsupported_operation
#    define ul_ctl_request_cache ulinternal_crash_unsupported_operation
#    define ul_ctl_set_cpu_model ulinternal_crash_unsupported_operation
#    define ul_ctl_set_exits ulinternal_crash_unsupported_operation
#    define ul_ctl_set_page_size ulinternal_crash_unsupported_operation
#endif
