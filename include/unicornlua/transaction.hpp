#pragma once

#include <unicorn/unicorn.h>
#if UC_API_MAJOR >= 2

#include "unicornlua/lua.hpp"

/**
 * Create a Lua table representation of a transaction block and push it to the
 * Lua stack.
 *
 * @param L
 * @param block
 */
void create_table_from_transaction_block(lua_State* L, const uc_tb* block);

#endif // UC_API_MAJOR
