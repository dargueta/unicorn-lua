#include <unicorn/unicorn.h>
#include <unicorn/x86.h>

#include "unicornlua/engine.h"
#include "unicornlua/hooks.h"
#include "unicornlua/lua.h"
#include "unicornlua/unicornlua.h"
#include "unicornlua/utils.h"


/**
 * A struct used for holding information about an active hook.
 */
typedef struct {
    lua_State *L;           /**< The Lua state used by this hook. */
    uc_engine *engine;      /**< The engine this hook is bound to. */
    uc_hook hook;           /**< The hook handle used by Unicorn. */

    /**
     * A reference in the global registry for this hook's callback function.
     */
    int callback_func_ref;

    /**
     * A reference in the global registry to a user-defined object to pass to
     * this hook's callback function.
     */
    int user_data_ref;
} HookInfo;


static void _get_callback_for_hook(const HookInfo *hook_data);
static void _get_hook_table_for_engine(lua_State *L, int index);
static HookInfo *_create_hook_object(lua_State *L, int eng_index, int cb_index);
static void *_get_c_callback_for_hook_type(int hook_type, int insn_code);


static void _get_hook_table_for_engine(lua_State *L, int index) {
    UCLuaEngine *engine_object = luaL_checkudata(L, index, kEngineMetatableName);
    lua_geti(L, LUA_REGISTRYINDEX, engine_object->hook_table_ref);

    if (lua_isnil(L, -1))
        luaL_error(L, "No hook table found for the given engine.");
}


static HookInfo *_create_hook_object(lua_State *L, int eng_index, int cb_index) {
    HookInfo *hook_info;

    _get_hook_table_for_engine(L, eng_index);

    hook_info = (HookInfo *)lua_newuserdata(L, sizeof(*hook_info));
    hook_info->L = L;
    hook_info->engine = ul_toengine(L, eng_index);
    hook_info->hook = 0;

    /* Push a copy of the callback function on the top of the stack and store a
     * reference to it in the registry. This will make it easy for C callbacks
     * to find the right Lua function to call. */
    lua_pushvalue(L, cb_index);
    hook_info->callback_func_ref = luaL_ref(L, LUA_REGISTRYINDEX);

    /* Callback function popped off the top. Hook object at TOS, followed by the
     * hook table.
     *
     * Store the hook in the hook table using a light userdata with the pointer
     * to the hook C struct as the key. */
    lua_pushlightuserdata(L, (void *)hook_info);
    lua_swaptoptwo(L);
    lua_settable(L, -3);

    return hook_info;
}


static void _get_callback_for_hook(const HookInfo *hook_data) {
    lua_State *L = hook_data->L;

    lua_geti(L, LUA_REGISTRYINDEX, hook_data->callback_func_ref);
    if (lua_isnil(L, -1))
        luaL_error(L, "No callback function found for the given hook.");
}


/* The C wrapper for a code execution hook. */
static void code_hook(uc_engine *uc, uint64_t address, uint32_t size,
                      void *user_data) {
    lua_State *L = ((HookInfo *)user_data)->L;

    /* Push the callback function onto the stack. */
    _get_callback_for_hook((HookInfo *)user_data);

    /* Push the arguments */
    ul_get_engine_object(L, uc);
    lua_pushinteger(L, (lua_Unsigned)address);
    lua_pushinteger(L, (lua_Unsigned)size);
    lua_geti(L, LUA_REGISTRYINDEX, ((HookInfo *)user_data)->user_data_ref);
    lua_call(L, 4, 0);
}


static void interrupt_hook(uc_engine *uc, uint32_t intno, void *user_data) {
    lua_State *L = ((HookInfo *)user_data)->L;

    /* Push the callback function onto the stack. */
    _get_callback_for_hook((HookInfo *)user_data);

    /* Push the arguments */
    ul_get_engine_object(L, uc);
    lua_pushinteger(L, (lua_Unsigned)intno);
    lua_geti(L, LUA_REGISTRYINDEX, ((HookInfo *)user_data)->user_data_ref);
    lua_call(L, 3, 0);
}


static uint32_t port_in_hook(uc_engine *uc, uint32_t port, int size,
                             void *user_data) {
    uint32_t return_value;
    lua_State *L = ((HookInfo *)user_data)->L;

    /* Push the callback function onto the stack. */
    _get_callback_for_hook((HookInfo *)user_data);

    /* Push the arguments */
    ul_get_engine_object(L, uc);
    lua_pushinteger(L, (lua_Unsigned)port);
    lua_pushinteger(L, (lua_Unsigned)size);
    lua_geti(L, LUA_REGISTRYINDEX, ((HookInfo *)user_data)->user_data_ref);
    lua_call(L, 4, 1);

    return_value = (uint32_t)luaL_checkinteger(L, -1);
    lua_pop(L, 1);

    return return_value;
}


static void port_out_hook(uc_engine *uc, uint32_t port, int size, uint32_t value,
                          void *user_data) {
    lua_State *L = ((HookInfo *)user_data)->L;

    /* Push the callback function onto the stack. */
    _get_callback_for_hook((HookInfo *)user_data);

    /* Push the arguments */
    ul_get_engine_object(L, uc);
    lua_pushinteger(L, (lua_Unsigned)port);
    lua_pushinteger(L, (lua_Unsigned)size);
    lua_pushinteger(L, (lua_Unsigned)value);
    lua_geti(L, LUA_REGISTRYINDEX, ((HookInfo *)user_data)->user_data_ref);
    lua_call(L, 5, 0);
}


static void memory_access_hook(uc_engine *uc, uc_mem_type type, uint64_t address,
                               int size, int64_t value, void *user_data) {
    lua_State *L = ((HookInfo *)user_data)->L;

    /* Push the callback function onto the stack. */
    _get_callback_for_hook((HookInfo *)user_data);

    /* Push the arguments */
    ul_get_engine_object(L, uc);
    lua_pushinteger(L, (lua_Integer)type);
    lua_pushinteger(L, (lua_Unsigned)address);
    lua_pushinteger(L, (lua_Unsigned)size);
    lua_pushinteger(L, (lua_Unsigned)value);
    lua_geti(L, LUA_REGISTRYINDEX, ((HookInfo *)user_data)->user_data_ref);
    lua_call(L, 6, 0);
}


static bool invalid_mem_access_hook(uc_engine *uc, uc_mem_type type,
                                    uint64_t address, int size, int64_t value,
                                    void *user_data) {
    bool return_value;
    lua_State *L = ((HookInfo *)user_data)->L;

    /* Push the callback function onto the stack. */
    _get_callback_for_hook((HookInfo *)user_data);

    /* Push the arguments */
    ul_get_engine_object(L, uc);
    lua_pushinteger(L, (lua_Integer)type);
    lua_pushinteger(L, (lua_Unsigned)address);
    lua_pushinteger(L, (lua_Unsigned)size);
    lua_pushinteger(L, (lua_Unsigned)value);
    lua_geti(L, LUA_REGISTRYINDEX, ((HookInfo *)user_data)->user_data_ref);
    lua_call(L, 6, 1);

    return_value = (bool)luaL_checkboolean(L, -1);
    lua_pop(L, 1);

    return return_value;
}


static void *_get_c_callback_for_hook_type(int hook_type, int insn_code) {
    switch (hook_type) {
        case UC_HOOK_INTR:
            return (void *)interrupt_hook;

        case UC_HOOK_BLOCK:
        case UC_HOOK_CODE:
            return (void *)code_hook;

        case UC_HOOK_INSN:
            /* TODO (dargueta): Support other architectures beside X86. */
            if (insn_code == UC_X86_INS_IN)
                return (void *)port_in_hook;
            else if (insn_code == UC_X86_INS_OUT)
                return (void *)port_out_hook;
            return (void *)code_hook;

        case UC_HOOK_MEM_FETCH:
        case UC_HOOK_MEM_READ:
        case UC_HOOK_MEM_READ_AFTER:
        case UC_HOOK_MEM_WRITE:
        case UC_HOOK_MEM_VALID:
            return (void *)memory_access_hook;

        case UC_HOOK_MEM_FETCH_INVALID:
        case UC_HOOK_MEM_FETCH_PROT:
        case UC_HOOK_MEM_FETCH_UNMAPPED:
        case UC_HOOK_MEM_INVALID:
        case UC_HOOK_MEM_PROT:
        case UC_HOOK_MEM_READ_INVALID:
        case UC_HOOK_MEM_READ_PROT:
        case UC_HOOK_MEM_READ_UNMAPPED:
        case UC_HOOK_MEM_UNMAPPED:
        case UC_HOOK_MEM_WRITE_INVALID:
        case UC_HOOK_MEM_WRITE_PROT:
        case UC_HOOK_MEM_WRITE_UNMAPPED:
            return (void *)invalid_mem_access_hook;

        default:
            return NULL;
    }
}


int ul_hook_add(lua_State *L) {
    HookInfo *hook_info;
    uint64_t start, end;
    uc_engine *engine;
    int error, hook_type, n_args, extra_argument;
    void *c_callback;

    n_args = lua_gettop(L);

    engine = ul_toengine(L, 1);
    hook_type = luaL_checkinteger(L, 2);
    /* Callback function is at position 3 */

    switch (n_args) {
        case 3:
            /* No start or end addresses given, assume hook applies to all of
             * memory. */
            start = 1;
            end = 0;
            break;
        case 4:
            /* Start address given but no end address. Presumably the user wants
             * the hook to apply for all memory at and above this address. */
            start = (uint64_t)luaL_optinteger(L, 4, 0);
            end = ~0;
            break;
        case 5:
        case 6:
        case 7:
            /* Start and end addresses given. */
            start = (uint64_t)luaL_optinteger(L, 4, 0);
            end = (uint64_t)luaL_optinteger(L, 5, ~0);
            break;
        default:
            return luaL_error(L, "Expected 3-7 arguments, got %d.", n_args);
    }

    hook_info = _create_hook_object(L, 1, 3);

    /* If the caller gave us a sixth argument, it's data to pass to the callback.
     * Create a reference to it and store that in the hook struct. */
    if (!lua_isnoneornil(L, 6)) {
        lua_pushvalue(L, 6);
        hook_info->user_data_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    }
    else
        hook_info->user_data_ref = LUA_NOREF;

    /* We can't use luaL_optinteger for argument 7 because there can be data at
     * index n_args + 1. We have to check the stack size first. */
    if (n_args >= 7)
        extra_argument = (int)luaL_checkinteger(L, 7);
    else
        extra_argument = LUA_NOREF;

    /* Figure out which C hook we need */
    c_callback = _get_c_callback_for_hook_type(hook_type, extra_argument);
    if (c_callback == NULL)
        return luaL_error(L, "Unrecognized hook type: %d", hook_type);

    if (n_args < 6)
        error = uc_hook_add(engine, &hook_info->hook, hook_type, c_callback,
                            (void *)hook_info, start, end);
    else
        error = uc_hook_add(engine, &hook_info->hook, hook_type, c_callback,
                            (void *)hook_info, start, end, extra_argument);

    if (error != UC_ERR_OK)
        return ul_crash_on_error(L, error);

    /* Return the hook struct as light userdata. Lua code can use this to remove
     * a hook before the engine is closed. */
    lua_pushlightuserdata(L, (void *)hook_info);
    return 1;
}


int ul_hook_del(lua_State *L) {
    ul_hook_del_by_indexes(L, 1, 2);
    return 0;
}


int ul_hook_del_by_indexes(lua_State *L, int engine_index, int hook_handle_index) {
    int error;
    HookInfo *hook_info;

    engine_index = lua_absindex(L, engine_index);
    hook_handle_index = lua_absindex(L, hook_handle_index);

    hook_info = (HookInfo *)luaL_checklightuserdata(L, hook_handle_index);

    /* Remove the hard reference to the hook's callback function, and overwrite
     * the reference ID in the C struct. This way, accidental reuse of the hook
     * struct will fail. */
    luaL_unref(L, LUA_REGISTRYINDEX, hook_info->callback_func_ref);
    luaL_unref(L, LUA_REGISTRYINDEX, hook_info->user_data_ref);
    hook_info->callback_func_ref = LUA_NOREF;
    hook_info->user_data_ref = LUA_NOREF;

    /* Remove the hook from the engine. */
    error = uc_hook_del(hook_info->engine, hook_info->hook);
    if (error != UC_ERR_OK)
        return ul_crash_on_error(L, error);

    /* Get the hook object table for this engine so we can remove the hook
     * object. */
    _get_hook_table_for_engine(L, engine_index);

    /* TOS is the hook table for this engine. Find the hook object associated
     * with the hook ID and remove it from the table. */
    lua_pushlightuserdata(L, (void *)hook_info);
    lua_pushnil(L);
    lua_settable(L, -3);

    /* Remove the hook table from the stack. */
    lua_pop(L, 1);

    return 0;
}
