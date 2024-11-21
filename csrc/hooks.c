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
#include "unicornlua/basic_hook_functions.h"
#include "unicornlua/utils.h"
#include <lauxlib.h>
#include <lua.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <unicorn/unicorn.h>

static void get_common_arguments(lua_State *restrict L, ULHookState *restrict hook,
                                 uc_engine **engine, uc_hook_type *restrict hook_type,
                                 uint64_t *restrict start_address,
                                 uint64_t *restrict end_address);

static bool ulinternal_hook_callback__invalid_mem_access(uc_engine *engine,
                                                         uc_mem_type type,
                                                         uint64_t address, int size,
                                                         int64_t value, void *userdata);

static uint32_t ulinternal_hook_callback__port_in(uc_engine *engine, uint32_t port,
                                                  int size, void *userdata);

/* ISO C forbids casting a function pointer to an object pointer (void* in this case). As
 * Unicorn requires us to do this, we have to disable pedantic warnings temporarily so
 * that the compiler doesn't blow up. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"

int ul_create_arm64_sys_hook(lua_State *L)
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

int ul_create_invalid_mem_access_hook(lua_State *L)
{
    ulinternal_helper_create_generic_hook(
        L, "invalid_mem_access", (void *)ulinternal_hook_callback__invalid_mem_access);
    return 1;
}

int ul_create_port_in_hook(lua_State *L)
{
    uc_engine *engine;
    uint64_t start_address, end_address;
    uc_hook_type hook_type;

#if LUA_VERSION_NUM >= 504
    ULHookState *hook_state = (ULHookState *)lua_newuserdatauv(L, sizeof(*hook_state), 0);
#else
    ULHookState *hook_state = (ULHookState *)lua_newuserdata(L, sizeof(*hook_state));
#endif

    get_common_arguments(L, hook_state, &engine, &hook_type, &start_address,
                         &end_address);

    uc_err error = uc_hook_add(engine, &hook_state->hook_handle, hook_type,
                               ulinternal_hook_callback__port_in, hook_state,
                               start_address, end_address, UC_X86_INS_IN);

    ulinternal_crash_if_failed(
        L, error,
        "Failed to create code hook for x86 instruction `in` from address 0x%08" PRIX64
        " through 0x%08" PRIX64 " (start > end means \"all of memory\")",
        start_address, end_address);
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

#pragma GCC diagnostic pop

static void get_common_arguments(lua_State *restrict L, ULHookState *restrict hook,
                                 uc_engine **engine, uc_hook_type *restrict hook_type,
                                 uint64_t *restrict start_address,
                                 uint64_t *restrict end_address)
{
    hook->L = L;
    hook->hook_handle = (uc_hook)0;
    *engine = (uc_engine *)lua_topointer(L, 1);
    *hook_type = (uc_hook_type)lua_tointeger(L, 2);
    *start_address = (uint64_t)lua_tointeger(L, 4);
    *end_address = (uint64_t)lua_tointeger(L, 5);

    /* The user's callback function is in stack position 3. To be able to call it later,
     * we save a strong reference to it in the C registry. Ideally we would save it in the
     * engine, but unfortunately there's weird behavior going on with a double free and
     * this is what works. */
    lua_pushlightuserdata(L, hook);
    lua_pushvalue(L, 3);
    lua_settable(L, LUA_REGISTRYINDEX);
}

void ulinternal_helper_create_generic_hook(lua_State *L, const char *human_readable,
                                           void *callback)
{
    uc_engine *engine;
    uint64_t start_address, end_address;
    uc_hook_type hook_type;

#if LUA_VERSION_NUM >= 504
    ULHookState *hook_state = (ULHookState *)lua_newuserdatauv(L, sizeof(*hook_state), 0);
#else
    ULHookState *hook_state = (ULHookState *)lua_newuserdata(L, sizeof(*hook_state));
#endif
    get_common_arguments(L, hook_state, &engine, &hook_type, &start_address,
                         &end_address);

    uc_err error = uc_hook_add(engine, &hook_state->hook_handle, hook_type, callback,
                               hook_state, start_address, end_address);

    ulinternal_crash_if_failed(
        L, error,
        "Failed to create hook of type %ld (called as `%s`) from address 0x%08" PRIX64
        " through 0x%08" PRIX64 " (start > end means \"all of memory\")",
        (long)hook_type, human_readable, start_address, end_address);
}

int ul_hook_del(lua_State *L)
{
    uc_engine *engine = (uc_engine *)lua_topointer(L, 1);
    ULHookState *hook = (ULHookState *)lua_topointer(L, 2);

    luaL_argcheck(L, hook->L != NULL, 2,
                  "Detected possible attempt to remove the same hook twice.");
    /* Try to retrieve the callback assigned to this hook. All we're doing is seeing if
     * the callback still exists in the registry. If it doesn't, something removed it
     * already. */
    int type_of_callback;

    lua_pushlightuserdata(L, hook);
#if LUA_VERSION_NUM >= 503
    type_of_callback = lua_gettable(L, LUA_REGISTRYINDEX);
#else
    lua_gettable(L, LUA_REGISTRYINDEX);
    type_of_callback = lua_type(L, -1);
#endif
    lua_pop(L, 1);
    luaL_argcheck(
        L, type_of_callback != LUA_TNIL, 2,
        "No callback was found for this hook. Either this argument isn't actually a hook,"
        " or the library has a bug in how the callback gets retrieved.");

    uc_err error = uc_hook_del(engine, hook->hook_handle);

    /* We're deliberately not destroying `hook` yet. If this function fails inside a
     * protected call, the user may want to try again later. */
    ulinternal_crash_if_failed(L, error, "Failed to unset hook.");

    /* Release the callback. */
    lua_pushlightuserdata(L, hook);
    lua_pushnil(L);
    lua_settable(L, LUA_REGISTRYINDEX);

    /* Corrupt the hook data. If Lua tries calling this function again and the memory that
     * `hook` points to is still valid, we'll catch the problem and throw an error instead
     * of segfaulting. */
    hook->L = NULL;
    return 0;
}

int ul_release_hook_callbacks(lua_State *L)
{
    int total_arguments = lua_gettop(L);

    for (int i = 1; i <= total_arguments; i++)
    {
        void *ud = lua_touserdata(L, i);
        lua_pushlightuserdata(L, ud);
        lua_pushnil(L);
        lua_settable(L, LUA_REGISTRYINDEX);
    }

    /* Return the total number of callbacks (possibly) deallocated. */
    lua_pushinteger(L, total_arguments);
    return 1;
}

void ulinternal_push_callback_to_lua(const ULHookState *hook)
{
    /* Retrieve the callback from the registry using this hook's metadata as the key. */
    lua_pushlightuserdata(hook->L, (void *)hook);
    lua_gettable(hook->L, LUA_REGISTRYINDEX);

    if (lua_isnil(hook->L, -1))
    {
        ulinternal_crash(
            hook->L,
            "No callback function was found for hook %p. This likely means it's been"
            " deleted already using Engine:hook_del().",
            (void *)hook);
    }
}

static bool ulinternal_hook_callback__invalid_mem_access(uc_engine *engine,
                                                         uc_mem_type type,
                                                         uint64_t address, int size,
                                                         int64_t value, void *userdata)
{
    (void)engine;
    ULHookState *hook = (ULHookState *)userdata;

    ulinternal_push_callback_to_lua(hook);
    lua_pushinteger(hook->L, (lua_Integer)type);
    lua_pushinteger(hook->L, (lua_Integer)address);
    lua_pushinteger(hook->L, (lua_Integer)size);
    /* TODO(dargueta): If type == UC_HOOK_MEM_READ_INVALID then pass `nil` for `value`.
     * While one shouldn't be using `value` on a read to begin with, I'll treat this as
     * backwards-incompatible, and hold off on making the change until v3.0. */
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
    ULHookState *hook = (ULHookState *)userdata;

    ulinternal_push_callback_to_lua(hook);
    lua_pushinteger(hook->L, (lua_Integer)port);
    lua_pushinteger(hook->L, (lua_Integer)size);
    lua_call(hook->L, 2, 1);

    uint32_t return_value = (uint32_t)luaL_checkinteger(hook->L, -1);
    lua_pop(hook->L, 1);
    return return_value;
}
