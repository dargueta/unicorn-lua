/**
 * Miscellaneous utilities used by the Unicorn Lua binding.
 *
 * @file utils.h
 */

#ifndef INCLUDE_UNICORNLUA_UTILS_H_
#define INCLUDE_UNICORNLUA_UTILS_H_

#include <unicorn/unicorn.h>

#include "unicornlua/lua.h"


/**
 * Throw a Lua error with a message derived from the given Unicorn error code.
 *
 * @param L         A pointer to the current Lua state.
 * @param error     A unicorn error code.
 *
 * @note Like lua_error, this function never returns, and should be treated in
 * exactly the same way.
 */
int ul_crash_on_error(lua_State *L, uc_err error);


/**
 * Return the value on the stack at @a index as a uc_context pointer.
 *
 * If the value at @a index is @e not a uc_context struct, or the context has
 * already been freed, a Lua error will be thrown.
 *
 * @param L         A pointer to the current Lua state.
 * @param index     The index of the value to return.
 */
uc_context *ul_tocontext(lua_State *L, int index);


/**
 * Create a new weak table with the given key mode, and push it onto the stack.
 *
 * @param L         A pointer to the current Lua state.
 * @param mode      The table mode to use. See the Lua documentation for a full
 *                  description of valid modes and how they work.
 */
void ul_create_weak_table(lua_State *L, const char *mode);

#endif  /* INCLUDE_UNICORNLUA_UTILS_H_ */
