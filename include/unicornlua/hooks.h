/**
 * @file hooks.h
 */

#ifndef INCLUDE_UNICORNLUA_HOOKS_H_
#define INCLUDE_UNICORNLUA_HOOKS_H_

#include "unicornlua/lua.h"

struct HookInfo_;
typedef struct HookInfo_ HookInfo;


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
 *   engine:hook_add(unicorn.UC_HOOK_MEM_READ_UNMAPPED, my_fn, nil, nil, my_data)
 * ```
 */
int ul_hook_add(lua_State *L);

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
int ul_hook_del(lua_State *L);


/**
 * Get the callback function for the given hook and push it on the stack.
 */
void ul_hook_get_callback(const HookInfo *hook_data);


void ul_destroy_hook(HookInfo *hook);

#endif  /* INCLUDE_UNICORNLUA_HOOKS_H_ */
