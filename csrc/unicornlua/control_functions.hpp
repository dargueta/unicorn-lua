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

#include "lua.hpp"

[[noreturn]] int ul_crash_unsupported_operation(lua_State *L);

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
#    define ul_ctl_exits_disable ul_crash_unsupported_operation
#    define ul_ctl_exits_enable ul_crash_unsupported_operation
#    define ul_ctl_flush_tlb ul_crash_unsupported_operation
#    define ul_ctl_get_arch ul_crash_unsupported_operation
#    define ul_ctl_get_cpu_model ul_crash_unsupported_operation
#    define ul_ctl_get_exits ul_crash_unsupported_operation
#    define ul_ctl_get_exits_cnt ul_crash_unsupported_operation
#    define ul_ctl_get_mode ul_crash_unsupported_operation
#    define ul_ctl_get_page_size ul_crash_unsupported_operation
#    define ul_ctl_get_timeout ul_crash_unsupported_operation
#    define ul_ctl_remove_cache ul_crash_unsupported_operation
#    define ul_ctl_request_cache ul_crash_unsupported_operation
#    define ul_ctl_set_cpu_model ul_crash_unsupported_operation
#    define ul_ctl_set_exits ul_crash_unsupported_operation
#    define ul_ctl_set_page_size ul_crash_unsupported_operation
#endif
