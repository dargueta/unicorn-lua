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
#include <stdint.h>
#include <unicorn/unicorn.h>

#pragma once

typedef struct
{
    uc_engine *engine;
    uc_hook_type hook_type;
    uint64_t start_address;
    uint64_t end_address;
    int callback_ref;
    uc_hook hook_handle;
    lua_State *L;
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
int ul_create_generic_hook_with_no_arguments(lua_State *L);
int ul_create_edge_generated_hook(lua_State *L);

void ulinternal_hook_callback__no_arguments(uc_engine *engine, void *userdata);
void ulinternal_hook_callback__interrupt(uc_engine *engine, uint32_t intno,
                                         void *userdata);
void ulinternal_hook_callback__memory_access(uc_engine *engine, uc_mem_type type,
                                             uint64_t address, int size, int64_t value,
                                             void *userdata);
