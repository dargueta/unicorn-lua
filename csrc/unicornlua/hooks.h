// Copyright (C) 2017-2025 by Diego Argueta
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

#include <lua.h>
#include <unicorn/unicorn.h>

#pragma once

typedef struct
{
    lua_State *L;
    uc_hook hook_handle;
} ULHookState;

void ulinternal_push_callback_to_lua(const ULHookState *hook);

int ul_hook_del(lua_State *L);
int ul_create_invalid_mem_access_hook(lua_State *L);
int ul_create_port_in_hook(lua_State *L);
int ul_create_arm64_sys_hook(lua_State *L);
int ul_create_cpuid_hook(lua_State *L);
int ul_create_edge_generated_hook(lua_State *L);
int ul_create_tcg_opcode_hook(lua_State *L);
int ul_release_hook_callbacks(lua_State *L);
void ulinternal_helper_create_generic_hook(lua_State *L, const char *human_readable,
                                           void *callback);
