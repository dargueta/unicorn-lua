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
#include <lauxlib.h>
#include <lua.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <unicorn/unicorn.h>

UL_RETURNS_POINTER
static ULHook *get_common_arguments(lua_State *L, uc_engine **engine,
                                    uc_hook_type *restrict hook_type,
                                    uint64_t *restrict start_address,
                                    uint64_t *restrict end_address);

static void helper_create_generic_hook(lua_State *L, const char *human_readable,
                                          void *callback);

static void helper_create_generic_code_hook(lua_State *L, void *callback);

static void push_callback_to_lua(const ULHook *hook);

static void ulinternal_hook_callback__generic_no_arguments(uc_engine *engine,
                                                           void *userdata);
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

#define define_hook_wrapper_function(slug)                                    \
    int ul_create_##slug##_hook(lua_State *L)                                 \
    {                                                                         \
        helper_create_generic_hook(L, #slug,                                  \
                                   (void *)ulinternal_hook_callback__##slug); \
        return 1;                                                             \
    }

define_hook_wrapper_function(interrupt);
define_hook_wrapper_function(memory_access);
define_hook_wrapper_function(invalid_mem_access);
define_hook_wrapper_function(generic_no_arguments);

#pragma GCC diagnostic pop

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

int ul_create_edge_generated_hook(lua_State *L)
{
#ifndef UC_HOOK_EDGE_GENERATED
    ulinternal_crash_unsupported_operation(L);
#else
    ulinternal_crash_not_implemented(L);
#endif
}

int ul_create_code_hook(lua_State *L)
{
    helper_create_generic_code_hook(L, ulinternal_hook_callback__code);
    return 1;
}

int ul_create_port_in_hook(lua_State *L)
{
    lua_pushinteger(L, (lua_Integer)UC_X86_INS_IN);
    helper_create_generic_code_hook(L, ulinternal_hook_callback__port_in);
    return 1;
}

int ul_create_port_out_hook(lua_State *L)
{
    lua_pushinteger(L, (lua_Integer)UC_X86_INS_OUT);
    helper_create_generic_code_hook(L, ulinternal_hook_callback__port_out);
    return 1;
}

int ul_create_tcg_opcode_hook(lua_State *L)
{
#ifndef UC_HOOK_TCG_OPCODE
    ulinternal_crash_unsupported_operation(L);
#else
    ulinternal_crash_not_implemented(L);
#endif
}

static ULHook *get_common_arguments(lua_State *L, uc_engine **engine,
                                    uc_hook_type *restrict hook_type,
                                    uint64_t *restrict start_address,
                                    uint64_t *restrict end_address)
{
    /* We could allocate the memory ourselves with malloc() and pass light userdata back
     * to the caller instead, but then we would have to do our own memory management. If
     * testing shows an adverse performance impact then we can change this. */
#if LUA_VERSION_NUM < 504
    ULHook *hook = lua_newuserdata(L, sizeof(*hook));
#else
    ULHook *hook = lua_newuserdatauv(L, sizeof(*hook), 0);
#endif

    hook->L = L;
    hook->hook_handle = (uc_hook)0;
    *engine = (uc_engine *)lua_topointer(L, 1);
    *hook_type = (uc_hook_type)lua_tointeger(L, 2);
    *start_address = (uint64_t)lua_tointeger(L, 4);
    *end_address = (uint64_t)lua_tointeger(L, 5);

    /* The user's callback function is in stack position 3. To be able to call it later,
     * we save a strong reference to it in the C registry. Ideally we would save it in the
     * userdata's uservalue slot, but when Unicorn calls our hook we won't have access to
     * that userdata. */
    lua_pushvalue(L, 3);
    hook->callback_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    return hook;
}

void helper_create_generic_hook(lua_State *L, const char *human_readable, void *callback)
{
    uc_engine *engine;
    uint64_t start_address, end_address;
    uc_hook_type hook_type;

    ULHook *hook =
        get_common_arguments(L, &engine, &hook_type, &start_address, &end_address);

    uc_err error = uc_hook_add(engine, &hook->hook_handle, hook_type, callback, hook,
                               start_address, end_address);

    ulinternal_crash_if_failed(
        L, error,
        "Failed to create hook of type %ld (called as `%s`) from address 0x%08" PRIX64
        " through 0x%08" PRIX64 " (start > end means \"all of memory\")",
        (long)hook_type, human_readable, start_address, end_address);
}

static void helper_create_generic_code_hook(lua_State *L, void *callback)
{
    uc_engine *engine;
    uint64_t start_address, end_address;
    uc_hook_type hook_type;

    ULHook *hook =
        get_common_arguments(L, &engine, &hook_type, &start_address, &end_address);

    int opcode = lua_tointeger(L, 6);
    uc_err error = uc_hook_add(engine, &hook->hook_handle, hook_type, callback, hook,
                               start_address, end_address, opcode);

    ulinternal_crash_if_failed(
        L, error,
        "Failed to create code hook for instruction ID %d from address 0x%08" PRIX64
        " through 0x%08" PRIX64 " (start > end means \"all of memory\")",
        opcode, start_address, end_address);
}

int ul_hook_del(lua_State *L)
{
    uc_engine *engine = (uc_engine *)lua_topointer(L, 1);
    ULHook *hook = (ULHook *)lua_touserdata(L, 2);

    if (hook->L == NULL || hook->callback_ref == LUA_NOREF)
        ulinternal_crash(L, "Detected attempt to remove same hook twice.");

    uc_err error = uc_hook_del(engine, hook->hook_handle);

    /* We're deliberately not destroying `hook` yet. If this function fails inside a
     * protected call, the user may want to try again later. */
    ulinternal_crash_if_failed(L, error, "Failed to unset hook.");

    /* Release the callback. */
    luaL_unref(L, LUA_REGISTRYINDEX, hook->callback_ref);

    /* Even though we're freeing the memory, accessing that address might still be valid
     * as far as the OS is concerned. We mark the callback field with an impossible value
     * in order to give ourselves a chance at catching a double free. */
    hook->L = NULL;
    hook->callback_ref = LUA_NOREF;
    return 0;
}

static void push_callback_to_lua(const ULHook *hook)
{
#if LUA_VERSION_NUM >= 503
    lua_geti(hook->L, LUA_REGISTRYINDEX, hook->callback_ref);
#else
    lua_pushinteger(hook->L, hook->callback_ref);
    lua_gettable(hook->L, LUA_REGISTRYINDEX);
#endif
}

static void ulinternal_hook_callback__generic_no_arguments(uc_engine *engine,
                                                           void *userdata)
{
    (void)engine;
    ULHook *hook = (ULHook *)userdata;
    push_callback_to_lua(hook);
    lua_call(hook->L, 0, 0);
}

static void ulinternal_hook_callback__interrupt(uc_engine *engine, uint32_t intno,
                                                void *userdata)
{
    (void)engine;
    ULHook *hook = (ULHook *)userdata;

    push_callback_to_lua(hook);
    lua_pushinteger(hook->L, (lua_Integer)intno);
    lua_call(hook->L, 1, 0);
}

static void ulinternal_hook_callback__memory_access(uc_engine *engine, uc_mem_type type,
                                                    uint64_t address, int size,
                                                    int64_t value, void *userdata)
{
    (void)engine;
    ULHook *hook = (ULHook *)userdata;

    push_callback_to_lua(hook);
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

    push_callback_to_lua(hook);
    lua_pushinteger(hook->L, (lua_Integer)type);
    lua_pushinteger(hook->L, (lua_Integer)address);
    lua_pushinteger(hook->L, (lua_Integer)size);
    lua_pushinteger(hook->L, (lua_Integer)value);
    lua_call(hook->L, 4, 1);

    if (lua_type(hook->L, -1) != LUA_TBOOLEAN)
    {
        luaL_error(hook->L,
                   "Error: Handler for invalid memory accesses must return a boolean,"
                   " got a %s instead.",
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

    push_callback_to_lua(hook);
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

    push_callback_to_lua(hook);
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

    push_callback_to_lua(hook);
    lua_pushinteger(hook->L, (lua_Integer)address);
    lua_pushinteger(hook->L, (lua_Integer)size);
    lua_call(hook->L, 2, 0);
}
