#include "unicornlua/hooks.h"
#include "unicornlua/utils.h"
#include <errno.h>
#include <lauxlib.h>
#include <lua.h>
#include <stdlib.h>
#include <string.h>
#include <unicorn/unicorn.h>

#ifdef __GNUC__
__attribute__((returns_nonnull, warn_unused_result))
#elif _MSC_VER
_Must_inspect_result_
#endif
static ULHook *
get_common_arguments(lua_State *L)
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

    /* The user's callback function is in stack position 3, custom user data is at stack
     * position 6 (if it exists). We can't assume the user data is at the top of the
     * stack because some hooks require arguments.
     *
     * First, we save a reference to the callback function into the registry. This lets us
     * keep a hard reference to it, ensuring the function will always exist when the hook
     * is triggered. The original copy is left on the stack at its original position.
     */
    lua_pushvalue(L, 3);
    hook->callback_ref = luaL_ref(L, LUA_REGISTRYINDEX);

    /* Similarly, we keep a hard reference to the userdata if it's not nil. */
    if (lua_isnil(L, 6))
        hook->extra_data_ref = LUA_REFNIL;
    else
    {
        lua_pushvalue(L, 6);
        hook->extra_data_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    }
    return hook;
}

int ul_create_interrupt_hook(lua_State *L)
{
    ulinternal_crash_not_implemented(L);
}

int ul_create_memory_access_hook(lua_State *L)
{
    ulinternal_crash_not_implemented(L);
}

int ul_create_invalid_mem_access_hook(lua_State *L)
{
    ulinternal_crash_not_implemented(L);
}

int ul_create_port_in_hook(lua_State *L)
{
    ulinternal_crash_not_implemented(L);
}

int ul_create_port_out_hook(lua_State *L)
{
    ulinternal_crash_not_implemented(L);
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
    ULHook *hook = get_common_arguments(L);

    uc_err error = uc_hook_add(hook->engine, &hook->hook_handle, hook->hook_type,
                               (void *)ulinternal_hook_callback__no_arguments, hook,
                               hook->start_address, hook->end_address);
    if (error != UC_ERR_OK)
    {
        int hook_type = (int)hook->hook_type;
        free(hook);
        ulinternal_crash_if_failed(L, error, "Failed to create generic hook of type %d",
                                   hook_type);
    }

    lua_pushlightuserdata(L, hook);
    return 1;
}

int ul_create_edge_generated_hook(lua_State *L)
{
    ulinternal_crash_not_implemented(L);
}

int ul_hook_del(lua_State *L)
{
    ULHook *hook = (ULHook *)lua_topointer(L, 1);
    uc_err error = uc_hook_del(hook->engine, hook->hook_handle);
    ulinternal_crash_if_failed(L, error, "Failed to unset hook.");

    luaL_unref(L, LUA_REGISTRYINDEX, hook->extra_data_ref);
    luaL_unref(L, LUA_REGISTRYINDEX, hook->callback_ref);
    free(hook);
    return 0;
}

void ulinternal_hook_callback__no_arguments(uc_engine *engine, void *userdata)
{
    (void)engine;
    ULHook *hook = (ULHook *)userdata;

    lua_geti(hook->L, LUA_REGISTRYINDEX, hook->callback_ref);
    lua_geti(hook->L, LUA_REGISTRYINDEX, hook->extra_data_ref);
    lua_call(hook->L, 1, 0);
}
