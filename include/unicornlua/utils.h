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
int uc_lua__crash_on_error(lua_State *L, int error);


/**
 * Given a uc_engine pointer, find the corresponding Lua object and push it.
 *
 * @param L         A pointer to the current Lua state.
 * @param engine    The pointer to the engine we want to get the Lua object for.
 */
void uc_lua__get_engine_object(lua_State *L, const uc_engine *engine);


/**
 * Return the value on the stack at @a index as a uc_context pointer.
 *
 * If the value at @a index is @e not a uc_context struct, or the context has
 * already been freed, a Lua error will be thrown.
 *
 * @param L         A pointer to the current Lua state.
 * @param index     The index of the value to return.
 */
uc_context *uc_lua__tocontext(lua_State *L, int index);


/**
 * Allocate/reallocate memory, or throw a Lua error on failure.
 */
void *uc_lua__realloc(lua_State *L, void *ptr, size_t new_size);


/**
 * Create a new weak table with the given key mode, and push it onto the stack.
 *
 * @param L         A pointer to the current Lua state.
 * @param mode      The table mode to use. See the Lua documentation for a full
 *                  description of valid modes and how they work.
 */
void uc_lua__create_weak_table(lua_State *L, const char *mode);

#endif  /* INCLUDE_UNICORNLUA_UTILS_H_ */
