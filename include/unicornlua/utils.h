/**
 * Miscellaneous utilities used by the Unicorn Lua binding.
 *
 * @file utils.h
 */

#pragma once

#include <new>
#include <stdexcept>

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
int ul_crash_on_error(lua_State* L, uc_err error);

/**
 * Create a new weak table with the given key mode, and push it onto the stack.
 *
 * @param L         A pointer to the current Lua state.
 * @param mode      The table mode to use. See the Lua documentation for a full
 *                  description of valid modes and how they work.
 */
void ul_create_weak_table(lua_State* L, const char* mode);

struct NamedIntConst {
    const char* name;
    lua_Integer value;
};

void load_int_constants(lua_State* L, const struct NamedIntConst* constants);

/**
 * Count the number of items in the table.
 *
 * `luaL_len()` only returns the number of entries in the array part of a table,
 * so this function iterates through the entirety of the table and returns the
 * result. */
size_t count_table_elements(lua_State* L, int table_index);
