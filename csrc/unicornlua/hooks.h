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

#include <lua.h>
#include <unicorn/unicorn.h>

#pragma once

typedef struct
{
    lua_State *L;
    uc_hook hook_handle;
    int callback_ref;
} ULHook;

int ul_hook_del(lua_State *L);
int ul_create_interrupt_hook(lua_State *L);
int ul_create_memory_access_hook(lua_State *L);
int ul_create_invalid_mem_access_hook(lua_State *L);
int ul_create_port_in_hook(lua_State *L);
int ul_create_port_out_hook(lua_State *L);
int ul_create_arm64_sys_hook(lua_State *L);
int ul_create_invalid_instruction_hook(lua_State *L);
int ul_create_cpuid_hook(lua_State *L);
int ul_create_generic_no_arguments_hook(lua_State *L);
int ul_create_edge_generated_hook(lua_State *L);
int ul_create_tcg_opcode_hook(lua_State *L);
int ul_create_code_hook(lua_State *L);
