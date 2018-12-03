#include <unicorn/unicorn.h>
#include <unicorn/x86.h>

#include "unicornlua/engine.h"
#include "unicornlua/hooks.h"
#include "unicornlua/lua.h"
#include "unicornlua/unicornlua.h"
#include "unicornlua/utils.h"

const char * const kHookMapName = "unicornlua__hook_map";
const char * const kHookMetatableName = "unicornlua__hook_meta";


typedef struct {
    lua_State *L;
    uc_engine *engine;
    uc_hook hook;
    int callback_func_ref;
} HookInfo;


static void _get_callback_for_hook(const HookInfo *hook_data);
static void _get_hook_table_for_engine(lua_State *L, int index);
static HookInfo *_create_hook_object(lua_State *L, int index);
static int _remove_hook(lua_State *L);
static void *_get_c_callback_for_hook_type(int hook_type, int insn_code);


static const luaL_Reg kHookMetamethods[] = {
    {"__gc", _remove_hook},
    {NULL, NULL}
};


void uc_lua__init_hooks_lib(lua_State *L) {
    /* Create a table with weak keys mapping the engine object to a table with
     * all of its hooks. */
    uc_lua__create_weak_table(L, "k");
    lua_setfield(L, LUA_REGISTRYINDEX, kHookMapName);

    luaL_newmetatable(L, kHookMetatableName);
    luaL_setfuncs(L, kHookMetamethods, 0);

    /* Remove the metatable from the stack. */
    lua_pop(L, 1);
}


static void _get_hook_table_for_engine(lua_State *L, int index) {
    lua_getfield(L, LUA_REGISTRYINDEX, kHookMapName);
    lua_pushvalue(L, index);
    lua_gettable(L, -2);

    /* Engine hook table at TOS, remove the engine/hook map right below it */
    lua_remove(L, -2);
}


void uc_lua__attach_hook_table(lua_State *L, int index) {
    /* Attempt to get a hook table for this engine, leaving the table on the
     * stack. We don't use _get_hook_table_for_engine() because that removes the
     * hook map and we'll need it later. */
    lua_getfield(L, LUA_REGISTRYINDEX, kHookMapName);
    lua_pushvalue(L, index);
    lua_gettable(L, -2);

    if (!lua_isnil(L, -1))
        luaL_error(L, "Refusing to create hook table; engine already has one.");

    lua_pushvalue(L, index);
    lua_newtable(L);
    lua_settable(L, -3);
    lua_pop(L, 1);      /* Remove engine's hook table */
}


static HookInfo *_create_hook_object(lua_State *L, int index) {
    HookInfo *hook_info;

    _get_hook_table_for_engine(L, index);
    if (lua_isnil(L, -1)) {
        lua_pop(L, 1);
        luaL_error(L, "Cannot create hook object: engine doesn't appear to have a table.");
    }

    hook_info = (HookInfo *)lua_newuserdata(L, sizeof(*hook_info));
    luaL_setmetatable(L, kHookMetatableName);

    hook_info->L = L;
    hook_info->engine = uc_lua__toengine(L, index);
    hook_info->hook = 0;

    /* Push a copy of the callback function on the top of the stack and store a
     * reference to it in the registry. This will make it easy for C callbacks
     * to find the right Lua function to call. */
    lua_movetotop(L, -3);
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


static int _remove_hook(lua_State *L) {
    HookInfo *hook_info;

    hook_info = (HookInfo *)luaL_checkudata(L, 1, kHookMetatableName);

    /* uc_lua__hook_del expects the engine as the first argument, so we need to
     * add it here. */
    uc_lua__get_engine_object(L, hook_info->engine);

    /* TOS is the engine, hook object is underneath it. We need the engine as
     * the first argument, hook object as the second. */
    lua_swaptoptwo(L);

    return uc_lua__hook_del(L);
}


static void _get_callback_for_hook(const HookInfo *hook_data) {
    lua_State *L = hook_data->L;

    lua_pushinteger(L, hook_data->callback_func_ref);
    lua_gettable(L, LUA_REGISTRYINDEX);

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
    uc_lua__get_engine_object(L, uc);
    lua_pushinteger(L, (lua_Unsigned)address);
    lua_pushinteger(L, (lua_Unsigned)size);
    lua_call(L, 3, 0);
}


static void interrupt_hook(uc_engine *uc, uint32_t intno, void *user_data) {
    lua_State *L = ((HookInfo *)user_data)->L;

    /* Push the callback function onto the stack. */
    _get_callback_for_hook((HookInfo *)user_data);

    /* Push the arguments */
    uc_lua__get_engine_object(L, uc);
    lua_pushinteger(L, (lua_Unsigned)intno);
    lua_call(L, 2, 0);
}


static uint32_t port_in_hook(uc_engine *uc, uint32_t port, int size,
                             void *user_data) {
    uint32_t return_value;
    lua_State *L = ((HookInfo *)user_data)->L;

    /* Push the callback function onto the stack. */
    _get_callback_for_hook((HookInfo *)user_data);

    /* Push the arguments */
    uc_lua__get_engine_object(L, uc);
    lua_pushinteger(L, (lua_Unsigned)port);
    lua_pushinteger(L, (lua_Unsigned)size);
    lua_call(L, 3, 1);

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
    uc_lua__get_engine_object(L, uc);
    lua_pushinteger(L, (lua_Unsigned)port);
    lua_pushinteger(L, (lua_Unsigned)size);
    lua_pushinteger(L, (lua_Unsigned)value);
    lua_call(L, 4, 0);
}


static void memory_access_hook(uc_engine *uc, uc_mem_type type, uint64_t address,
                               int size, int64_t value, void *user_data) {
    lua_State *L = ((HookInfo *)user_data)->L;

    /* Push the callback function onto the stack. */
    _get_callback_for_hook((HookInfo *)user_data);

    /* Push the arguments */
    uc_lua__get_engine_object(L, uc);
    lua_pushinteger(L, (lua_Integer)type);
    lua_pushinteger(L, (lua_Unsigned)address);
    lua_pushinteger(L, (lua_Unsigned)size);
    lua_pushinteger(L, (lua_Unsigned)value);
    lua_call(L, 5, 0);
}


static bool invalid_mem_access_hook(uc_engine *uc, uc_mem_type type,
                                    uint64_t address, int size, int64_t value,
                                    void *user_data) {
    bool return_value;
    lua_State *L = ((HookInfo *)user_data)->L;

    /* Push the callback function onto the stack. */
    _get_callback_for_hook((HookInfo *)user_data);

    /* Push the arguments */
    uc_lua__get_engine_object(L, uc);
    lua_pushinteger(L, (lua_Integer)type);
    lua_pushinteger(L, (lua_Unsigned)address);
    lua_pushinteger(L, (lua_Unsigned)size);
    lua_pushinteger(L, (lua_Unsigned)value);
    lua_call(L, 5, 1);

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


int uc_lua__hook_add(lua_State *L) {
    HookInfo *hook_info;
    uint64_t start, end;
    uc_engine *engine;
    int error, hook_type, n_args;
    lua_Integer extra_argument;
    void *c_callback;

    n_args = lua_gettop(L);
    if ((n_args < 3) || (n_args > 6))
        luaL_error(L, "Expected 3-6 arguments, got %d.", n_args);

    engine = uc_lua__toengine(L, 1);
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
            start = (uint64_t)luaL_checkinteger(L, 4);
            end = ~0;
            break;
        case 5:
        case 6:
            /* Start and end addresses given. */
            start = (uint64_t)luaL_checkinteger(L, 4);
            end = (uint64_t)luaL_checkinteger(L, 5);
            break;
        default:
            return luaL_error(L, "Expected 3-6 arguments, got %d.", n_args);
    }

    extra_argument = luaL_optinteger(L, 6, ~0);

    /* _create_hook_object expects the callback function to be at TOS. Move it,
     * then create the hook object. */
    lua_movetotop(L, 3);
    hook_info = _create_hook_object(L, 1);

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
        return uc_lua__crash_on_error(L, error);

    /* Return the hook struct as light userdata. Lua code can use this to remove
     * a hook before the engine is closed. */
    lua_pushlightuserdata(L, (void *)hook_info);
    return 1;
}


int uc_lua__hook_del(lua_State *L) {
    int error;
    HookInfo *hook_info;

    hook_info = (HookInfo *)luaL_checklightuserdata(L, 2);

    /* Remove the hard reference to the hook's callback function, and overwrite
     * the reference ID in the C struct. This way, accidental reuse of the hook
     * struct will fail. */
    luaL_unref(L, LUA_REGISTRYINDEX, hook_info->callback_func_ref);
    hook_info->callback_func_ref = LUA_NOREF;

    /* Remove the hook from the engine. */
    error = uc_hook_del(hook_info->engine, hook_info->hook);
    if (error != UC_ERR_OK)
        return uc_lua__crash_on_error(L, error);

    /* Get the hook object table for this engine so we can remove the hook
     * object. */
    _get_hook_table_for_engine(L, 1);

    /* TOS is the hook table for this engine. Find the hook object associated
     * with the hook ID and remove it from the table. */
    lua_pushlightuserdata(L, (void *)hook_info);
    lua_pushnil(L);
    lua_settable(L, -3);

    return 0;
}
