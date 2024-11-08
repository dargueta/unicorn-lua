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

#include "unicornlua/hooks.h"
#include "unicornlua/utils.h"
#include <errno.h>
#include <lauxlib.h>
#include <lua.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unicorn/unicorn.h>

UL_RETURNS_POINTER
static ULHook *get_common_arguments(lua_State *L);
UL_RETURNS_POINTER
static ULHook *helper_create_generic_hook(lua_State *L, void *callback);

static void ulinternal_hook_callback__no_arguments(uc_engine *engine, void *userdata);
static void ulinternal_hook_callback__interrupt(uc_engine *engine, uint32_t intno,
                                                void *userdata);
static void ulinternal_hook_callback__memory_access(uc_engine *engine, uc_mem_type type,
                                                    uint64_t address, int size,
                                                    int64_t value, void *userdata);
static bool ulinternal_hook_callback__invalid_mem_access(uc_engine *engine,
                                                         uc_mem_type type,
                                                         uint64_t address, int size,
                                                         int64_t value, void *userdata);

static uint32_t ulinternal_hook_callback__port_in(uc_engine *engine, uint32_t port,
                                                  int size, void *userdata);
static void ulinternal_hook_callback__port_out(uc_engine *engine, uint32_t port, int size,
                                               uint32_t value, void *userdata);
static void ulinternal_hook_callback__code(uc_engine *engine, uint64_t address,
                                           uint32_t size, void *userdata);



/* ISO C forbids casting a function pointer to an object pointer (void* in this case). As
 * Unicorn requires us to do this, we have to disable pedantic warnings temporarily so
 * that the compiler doesn't blow up. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"

int ul_create_interrupt_hook(lua_State *L)
{
    ULHook *hook =
        helper_create_generic_hook(L, (void *)ulinternal_hook_callback__interrupt);
    lua_pushlightuserdata(L, hook);
    return 1;
}

int ul_create_memory_access_hook(lua_State *L)
{
    ULHook *hook =
        helper_create_generic_hook(L, (void *)ulinternal_hook_callback__memory_access);
    lua_pushlightuserdata(L, hook);
    return 1;
}

int ul_create_invalid_mem_access_hook(lua_State *L)
{
    ULHook *hook = helper_create_generic_hook(
        L, (void *)ulinternal_hook_callback__invalid_mem_access);
    lua_pushlightuserdata(L, hook);
    return 1;
}

int ul_create_port_in_hook(lua_State *L)
{
    ULHook *hook =
        helper_create_generic_hook(L, (void *)ulinternal_hook_callback__port_in);
    lua_pushlightuserdata(L, hook);
    return 1;
}

int ul_create_port_out_hook(lua_State *L)
{
    ULHook *hook =
        helper_create_generic_hook(L, (void *)ulinternal_hook_callback__port_out);
    lua_pushlightuserdata(L, hook);
    return 1;
}

int ul_create_arm64_sys_hook(lua_State *L)
{
    ulinternal_crash_not_implemented(L);
}

int ul_create_invalid_instruction_hook(lua_State *L)
{
    ulinternal_crash_not_implemented(L);
}

int ul_create_cpuid_hook(lua_State *L)
{
    ulinternal_crash_not_implemented(L);
}

int ul_create_generic_hook_with_no_arguments(lua_State *L)
{
    ULHook *hook =
        helper_create_generic_hook(L, (void *)ulinternal_hook_callback__no_arguments);
    lua_pushlightuserdata(L, hook);
    return 1;
}

int ul_create_edge_generated_hook(lua_State *L)
{
    ulinternal_crash_not_implemented(L);
}

int ul_create_tcg_opcode_hook(lua_State *L)
{
    ulinternal_crash_not_implemented(L);
}

int ul_create_code_hook(lua_State *L)
{
    ULHook *hook = helper_create_generic_hook(L, (void *)ulinternal_hook_callback__code);
    lua_pushlightuserdata(L, hook);
    return 1;
}

#pragma GCC diagnostic pop

static ULHook *get_common_arguments(lua_State *L)
{
    ULHook *hook = malloc(sizeof(*hook));
    if (hook == NULL)
    {
        ulinternal_crash(L, "Failed to allocate memory for creating a hook: %s",
                         strerror(errno));
    }

    hook->L = L;
    hook->engine = (uc_engine *)lua_topointer(L, 1);
    hook->hook_type = (uc_hook_type)lua_tointeger(L, 2);
    hook->start_address = (uint64_t)lua_tointeger(L, 4);
    hook->end_address = (uint64_t)lua_tointeger(L, 5);

    /* The user's callback function is in stack position 3. To be able to call it later,
     * we save a strong reference to it in the registry. This ensures the function will
     * always exist when the hook is triggered. */
    lua_pushvalue(L, 3);
    hook->callback_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    return hook;
}

ULHook *helper_create_generic_hook(lua_State *L, void *callback)
{
    ULHook *hook = get_common_arguments(L);

    uc_err error = uc_hook_add(hook->engine, &hook->hook_handle, hook->hook_type,
                               callback, hook, hook->start_address, hook->end_address);

    if (error != UC_ERR_OK)
    {
        /* Because we need to free `hook` to avoid a memory leak, we need to copy out
         * arguments we're going to use in the error message. Annoying, but necessary. */
        int hook_type = (int)hook->hook_type;
        uint64_t start = hook->start_address;
        uint64_t end = hook->end_address;
        free(hook);

        ulinternal_crash_if_failed(
            L, error,
            "Failed to create generic hook of type %d from address 0x%08" PRIX64
            " through 0x%08" PRIX64 " (start > end means \"all of memory\")",
            hook_type, start, end);
    }

    return hook;
}

int ul_hook_del(lua_State *L)
{
    ULHook *hook = (ULHook *)lua_topointer(L, 1);
    uc_err error = uc_hook_del(hook->engine, hook->hook_handle);

    /* We're deliberately not deallocating `hook` yet. If this function fails inside a
     * protected call, the user may want to try again later. */
    ulinternal_crash_if_failed(L, error, "Failed to unset hook.");

    luaL_unref(L, LUA_REGISTRYINDEX, hook->callback_ref);
    hook->engine = NULL;
    free(hook);
    return 0;
}

static void ulinternal_hook_callback__no_arguments(uc_engine *engine, void *userdata)
{
    (void)engine;
    ULHook *hook = (ULHook *)userdata;

    lua_geti(hook->L, LUA_REGISTRYINDEX, hook->callback_ref);
    lua_call(hook->L, 0, 0);
}

static void ulinternal_hook_callback__interrupt(uc_engine *engine, uint32_t intno,
                                                void *userdata)
{
    (void)engine;
    ULHook *hook = (ULHook *)userdata;

    lua_geti(hook->L, LUA_REGISTRYINDEX, hook->callback_ref);
    lua_pushinteger(hook->L, (lua_Integer)intno);
    lua_call(hook->L, 1, 0);
}

static void ulinternal_hook_callback__memory_access(uc_engine *engine, uc_mem_type type,
                                                    uint64_t address, int size,
                                                    int64_t value, void *userdata)
{
    (void)engine;
    ULHook *hook = (ULHook *)userdata;

    lua_geti(hook->L, LUA_REGISTRYINDEX, hook->callback_ref);
    lua_pushinteger(hook->L, (lua_Integer)type);
    lua_pushinteger(hook->L, (lua_Integer)address);
    lua_pushinteger(hook->L, (lua_Integer)size);
    lua_pushinteger(hook->L, (lua_Integer)value);
    lua_call(hook->L, 4, 0);
}

static bool ulinternal_hook_callback__invalid_mem_access(uc_engine *engine,
                                                         uc_mem_type type,
                                                         uint64_t address, int size,
                                                         int64_t value, void *userdata)
{
    (void)engine;
    ULHook *hook = (ULHook *)userdata;

    /* Push the callback function onto the stack. */
    lua_geti(hook->L, LUA_REGISTRYINDEX, hook->callback_ref);

    /* Push the arguments */
    lua_pushinteger(hook->L, (lua_Integer)type);
    lua_pushinteger(hook->L, (lua_Integer)address);
    lua_pushinteger(hook->L, (lua_Integer)size);
    lua_pushinteger(hook->L, (lua_Integer)value);
    lua_call(hook->L, 4, 1);

    if (lua_type(hook->L, -1) != LUA_TBOOLEAN)
    {
        luaL_error(hook->L,
                   "Error: Handler for invalid memory accesses must return a boolean, "
                   "got a %s instead.",
                   lua_typename(hook->L, -1));
        UL_UNREACHABLE_MARKER;
    }
    int return_value = lua_toboolean(hook->L, -1);
    lua_pop(hook->L, 1);
    return return_value != 0;
}

static uint32_t ulinternal_hook_callback__port_in(uc_engine *engine, uint32_t port,
                                                  int size, void *userdata)
{
    (void)engine;
    ULHook *hook = (ULHook *)userdata;

    lua_geti(hook->L, LUA_REGISTRYINDEX, hook->callback_ref);
    lua_pushinteger(hook->L, (lua_Integer)port);
    lua_pushinteger(hook->L, (lua_Integer)size);
    lua_call(hook->L, 2, 1);

    uint32_t return_value = (uint32_t)luaL_checkinteger(hook->L, -1);
    lua_pop(hook->L, 1);
    return return_value;
}

static void ulinternal_hook_callback__port_out(uc_engine *engine, uint32_t port, int size,
                                               uint32_t value, void *userdata)
{
    (void)engine;
    ULHook *hook = (ULHook *)userdata;

    lua_geti(hook->L, LUA_REGISTRYINDEX, hook->callback_ref);
    lua_pushinteger(hook->L, (lua_Integer)port);
    lua_pushinteger(hook->L, (lua_Integer)size);
    lua_pushinteger(hook->L, (lua_Integer)value);
    lua_call(hook->L, 3, 0);
}

static void ulinternal_hook_callback__code(uc_engine *engine, uint64_t address,
                                           uint32_t size, void *userdata)
{
    (void)engine;
    ULHook *hook = (ULHook *)userdata;

    lua_geti(hook->L, LUA_REGISTRYINDEX, hook->callback_ref);
    lua_pushinteger(hook->L, (lua_Integer)address);
    lua_pushinteger(hook->L, (lua_Integer)size);
    lua_call(hook->L, 2, 0);
}
