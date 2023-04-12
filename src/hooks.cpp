#include <unicorn/unicorn.h>
#include <unicorn/x86.h>

#include "unicornlua/engine.h"
#include "unicornlua/errors.h"
#include "unicornlua/hooks.h"
#include "unicornlua/lua.h"
#include "unicornlua/utils.h"

Hook::Hook(lua_State* L, uc_engine* engine)
    : L_(L)
    , engine_(engine)
    , hook_handle_(0)
    , callback_func_ref_(LUA_NOREF)
    , user_data_ref_(LUA_REFNIL)
    , is_handle_set_(false)
{
}

Hook::Hook(lua_State* L, uc_engine* engine, uc_hook hook_handle,
    int callback_func_ref, int user_data_ref)
    : L_(L)
    , engine_(engine)
    , hook_handle_(hook_handle)
    , callback_func_ref_(callback_func_ref)
    , user_data_ref_(user_data_ref)
    , is_handle_set_(true)
{
}

Hook::~Hook() noexcept(false)
{
    if ((callback_func_ref_ != LUA_NOREF) && (callback_func_ref_ != LUA_REFNIL))
        luaL_unref(L_, LUA_REGISTRYINDEX, callback_func_ref_);

    if ((user_data_ref_ != LUA_NOREF) && (user_data_ref_ != LUA_REFNIL))
        luaL_unref(L_, LUA_REGISTRYINDEX, user_data_ref_);

    if (is_handle_set_) {
        uc_err error = uc_hook_del(engine_, hook_handle_);
        if (error != UC_ERR_OK)
            throw UnicornLibraryError(error);
    }
}

uc_engine* Hook::engine() noexcept { return engine_; }

lua_State* Hook::L() noexcept { return L_; }

uc_hook Hook::get_hook_handle() const noexcept { return hook_handle_; }

void Hook::set_hook_handle(uc_hook hook_handle) noexcept
{
    hook_handle_ = hook_handle;
    is_handle_set_ = true;
}

int Hook::set_callback(int cb_index)
{
    lua_pushvalue(L_, cb_index);
    int new_callback_ref = luaL_ref(L_, LUA_REGISTRYINDEX);

    if ((callback_func_ref_ != LUA_NOREF) && (callback_func_ref_ != LUA_REFNIL))
        luaL_unref(L_, LUA_REGISTRYINDEX, callback_func_ref_);
    callback_func_ref_ = new_callback_ref;
    return new_callback_ref;
}

int Hook::get_callback() const noexcept { return callback_func_ref_; }

void Hook::push_callback()
{
    lua_geti(L_, LUA_REGISTRYINDEX, callback_func_ref_);
}

int Hook::set_user_data(int ud_index)
{
    lua_pushvalue(L_, ud_index);
    int new_data_ref = luaL_ref(L_, LUA_REGISTRYINDEX);

    if ((user_data_ref_ != LUA_NOREF) && (user_data_ref_ != LUA_REFNIL))
        luaL_unref(L_, LUA_REGISTRYINDEX, user_data_ref_);
    user_data_ref_ = new_data_ref;
    return new_data_ref;
}

int Hook::get_user_data() const noexcept { return user_data_ref_; }

void Hook::push_user_data() { lua_geti(L_, LUA_REGISTRYINDEX, user_data_ref_); }

static void* get_c_callback_for_hook_type(int hook_type, int insn_code);

static void get_callback(Hook* hook)
{
    lua_State* L = hook->L();
    hook->push_callback();
    if (lua_isnil(L, -1))
        luaL_error(L,
            "No callback function found for hook %p attached to engine %p",
            hook, hook->engine());
}

/* The C wrapper for a code execution hook. */
static void code_hook(
    uc_engine* uc, uint64_t address, uint32_t size, void* user_data)
{
    auto hook = reinterpret_cast<Hook*>(user_data);
    lua_State* L = hook->L();

    /* Push the callback function onto the stack. */
    get_callback(hook);

    /* Push the arguments */
    ul_get_engine_object(L, uc);
    lua_pushinteger(L, static_cast<lua_Integer>(address));
    lua_pushinteger(L, static_cast<lua_Integer>(size));
    hook->push_user_data();
    lua_call(L, 4, 0);
}

static void interrupt_hook(uc_engine* uc, uint32_t intno, void* user_data)
{
    auto hook = reinterpret_cast<Hook*>(user_data);
    lua_State* L = hook->L();

    /* Push the callback function onto the stack. */
    get_callback(hook);

    /* Push the arguments */
    ul_get_engine_object(L, uc);
    lua_pushinteger(L, static_cast<lua_Integer>(intno));
    hook->push_user_data();
    lua_call(L, 3, 0);
}

static uint32_t port_in_hook(
    uc_engine* uc, uint32_t port, int size, void* user_data)
{
    auto hook = reinterpret_cast<Hook*>(user_data);
    lua_State* L = hook->L();

    /* Push the callback function onto the stack. */
    get_callback(hook);

    /* Push the arguments */
    ul_get_engine_object(L, uc);
    lua_pushinteger(L, static_cast<lua_Integer>(port));
    lua_pushinteger(L, static_cast<lua_Integer>(size));
    hook->push_user_data();
    lua_call(L, 4, 1);

    auto return_value = static_cast<uint32_t>(luaL_checkinteger(L, -1));
    lua_pop(L, 1);

    return return_value;
}

static void port_out_hook(
    uc_engine* uc, uint32_t port, int size, uint32_t value, void* user_data)
{
    auto hook = reinterpret_cast<Hook*>(user_data);
    lua_State* L = hook->L();

    /* Push the callback function onto the stack. */
    get_callback(hook);

    /* Push the arguments */
    ul_get_engine_object(L, uc);
    lua_pushinteger(L, static_cast<lua_Integer>(port));
    lua_pushinteger(L, static_cast<lua_Integer>(size));
    lua_pushinteger(L, static_cast<lua_Integer>(value));
    hook->push_user_data();
    lua_call(L, 5, 0);
}

static void memory_access_hook(uc_engine* uc, uc_mem_type type,
    uint64_t address, int size, int64_t value, void* user_data)
{
    auto hook = reinterpret_cast<Hook*>(user_data);
    lua_State* L = hook->L();

    /* Push the callback function onto the stack. */
    get_callback(hook);

    /* Push the arguments */
    ul_get_engine_object(L, uc);
    lua_pushinteger(L, (lua_Integer)type);
    lua_pushinteger(L, static_cast<lua_Integer>(address));
    lua_pushinteger(L, static_cast<lua_Integer>(size));
    lua_pushinteger(L, static_cast<lua_Integer>(value));
    hook->push_user_data();
    lua_call(L, 6, 0);
}

static bool invalid_mem_access_hook(uc_engine* uc, uc_mem_type type,
    uint64_t address, int size, int64_t value, void* user_data)
{
    auto hook = reinterpret_cast<Hook*>(user_data);
    lua_State* L = hook->L();

    /* Push the callback function onto the stack. */
    get_callback(hook);

    /* Push the arguments */
    ul_get_engine_object(L, uc);
    lua_pushinteger(L, static_cast<lua_Integer>(type));
    lua_pushinteger(L, static_cast<lua_Integer>(address));
    lua_pushinteger(L, static_cast<lua_Integer>(size));
    lua_pushinteger(L, static_cast<lua_Integer>(value));
    hook->push_user_data();
    lua_call(L, 6, 1);

    if (lua_type(L, -1) != LUA_TBOOLEAN) {
        luaL_error(L,
            "Error: Handler for invalid memory accesses must return a boolean, "
            "got a %s"
            " instead.",
            lua_typename(L, -1));
        // Technically this is unreachable because luaL_error calls longjmp().
        // The header doesn't declare this, however, so we have no way of
        // indicating this to the compiler unless we're on C++20 or higher.
        return false;
    }
    int return_value = lua_toboolean(L, -1);
    lua_pop(L, 1);
    return return_value != 0;
}

static void* get_c_callback_for_hook_type(int hook_type, int insn_code)
{
    switch (hook_type) {
    case UC_HOOK_INTR:
        return (void*)interrupt_hook;

    case UC_HOOK_BLOCK:
    case UC_HOOK_CODE:
        return (void*)code_hook;

    case UC_HOOK_INSN:
        /* TODO (dargueta): Support other architectures beside X86. */
        if (insn_code == UC_X86_INS_IN)
            return (void*)port_in_hook;
        else if (insn_code == UC_X86_INS_OUT)
            return (void*)port_out_hook;
        return (void*)code_hook;

    case UC_HOOK_MEM_FETCH:
    case UC_HOOK_MEM_READ:
    case UC_HOOK_MEM_READ_AFTER:
    case UC_HOOK_MEM_WRITE:
    case UC_HOOK_MEM_VALID:
        return (void*)memory_access_hook;

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
        return (void*)invalid_mem_access_hook;

    default:
        return nullptr;
    }
}

int ul_hook_add(lua_State* L)
{
    uint64_t start, end;
    int extra_argument;
    uc_err error;

    int n_args = lua_gettop(L);

    auto engine_object = get_engine_struct(L, 1);
    int hook_type = static_cast<int>(luaL_checkinteger(L, 2));
    /* Callback function is at position 3 */

    switch (n_args) {
    case 3:
        /* No start or end addresses given, assume hook applies to all of
         * RAM. */
        start = 1;
        end = 0;
        break;
    case 4:
        /* Start address given but no end address. Presumably the user wants
         * the hook to apply for all memory at and above this address. */
        start = (uint64_t)luaL_optinteger(L, 4, 0);
        end = UINT64_MAX;
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

    Hook* hook_info = engine_object->create_empty_hook();
    hook_info->set_callback(3);

    /* If the caller gave us a sixth argument, it's data to pass to the
     * callback. Create a reference to it and store that in the hook struct. */
    if (!lua_isnoneornil(L, 6))
        hook_info->set_user_data(6);

    /* We can't use luaL_optinteger for argument 7 because there can be data at
     * index n_args + 1. We have to check the stack size first. */
    if (n_args >= 7)
        extra_argument = static_cast<int>(luaL_checkinteger(L, 7));
    else
        extra_argument = LUA_NOREF;

    /* Figure out which C hook we need */
    void* c_callback = get_c_callback_for_hook_type(hook_type, extra_argument);
    if (c_callback == nullptr) {
        engine_object->remove_hook(hook_info);
        return luaL_error(L, "Unrecognized hook type: %d", hook_type);
    }

    uc_hook hook_handle;
    uc_engine* engine_handle = engine_object->get_handle();

    if (n_args < 6)
        error = uc_hook_add(engine_handle, &hook_handle, hook_type, c_callback,
            hook_info, start, end);
    else
        error = uc_hook_add(engine_handle, &hook_handle, hook_type, c_callback,
            hook_info, start, end, extra_argument);

    if (error != UC_ERR_OK) {
        engine_object->remove_hook(hook_info);
        return ul_crash_on_error(L, error);
    }

    hook_info->set_hook_handle(hook_handle);

    // Return the hook struct as light userdata. Lua code can use this to remove
    // a hook before the engine is closed. Hooks will remain attached even if
    // this handle gets garbage-collected.
    lua_pushlightuserdata(L, (void*)hook_info);
    return 1;
}

int ul_hook_del(lua_State* L)
{
    auto hook_info = (Hook*)lua_touserdata(L, 2);
    auto engine = get_engine_struct(L, 1);

    engine->remove_hook(hook_info);
    return 0;
}
