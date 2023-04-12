/**
 * @file hooks.h
 */

#pragma once

#include <unicorn/unicorn.h>

#include "unicornlua/lua.h"

class Hook {
    friend class UCLuaEngine;

protected:
    Hook(lua_State* L, uc_engine* engine);
    Hook(lua_State* L, uc_engine* engine, uc_hook hook_handle,
        int callback_func_ref = LUA_NOREF, int user_data_ref = LUA_REFNIL);

public:
    ~Hook() noexcept(false);

    uc_engine* engine() noexcept;
    lua_State* L() noexcept;
    uc_hook get_hook_handle() const noexcept;
    void set_hook_handle(uc_hook hook_handle) noexcept;

    int set_callback(int cb_index);
    int get_callback() const noexcept;
    void push_callback();

    int set_user_data(int ud_index);
    int get_user_data() const noexcept;
    void push_user_data();

private:
    lua_State* L_; ///< The Lua state used by this hook.
    uc_engine* engine_; ///< The engine this hook is bound to.
    uc_hook hook_handle_; ///< The hook handle used by Unicorn.

    /**
     * A reference in the global registry for this hook's callback function.
     */
    int callback_func_ref_;

    /**
     * A reference in the global registry to a user-defined object to pass to
     * this hook's callback function.
     */
    int user_data_ref_;
    bool is_handle_set_;
};

/**
 * Create a hook. Implements `engine:hook_add()`.
 *
 * The Lua method takes three to seven arguments depending on the kind of hook
 * being created. The first three arguments are *always* the engine, the hook
 * type, and the callback function, in that order. The next four arguments are
 * defined as follows:
 *
 * * 4: An integer marking the lowest memory address where the hook is active.
 *   If not given or `nil`, defaults to 0.
 * * 5: The inclusive upper bound where this hook is active. If not given or
 *   `nil`, defaults to the highest representable address for the host machine.
 * * 6: Custom data to pass to the hook callback. This can be anything. Keep in
 *   mind that a hard reference is created to this argument, so it can't be
 *   garbage collected until the hook is deleted.
 * * 7: The extra argument to pass to `uc_hook_add()`, if required. Currently
 *   passing only one extra argument is supported. See the documentation for
 *   `uc_hook_add()` to see when extra arguments are needed.
 *
 * `nil` can be explicitly passed to any argument as needed. For example, if you
 * want a hook to apply to all memory but also need to pass custom data to your
 * callback, you can pass `nil` as arguments 4 and 5:
 *
 * ```lua
 *   -- `engine` is implicit first argument
 *
 *   engine:hook_add(unicorn.UC_HOOK_MEM_READ_UNMAPPED, my_fn, nil, nil,
 * my_data)
 * ```
 */
int ul_hook_add(lua_State* L);

/**
 * Delete a hook. Implements `engine:hook_del()`.
 *
 * The Lua method takes two arguments:
 *
 * * The engine the hook is attached to
 * * The hook handle as returned by `engine:hook_add()`.
 *
 * Nothing is returned.
 */
int ul_hook_del(lua_State* L);
