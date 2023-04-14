#include <unicorn/unicorn.h>

#if UC_API_MAJOR >= 2
#include "unicornlua/lua.hpp"
#include "unicornlua/transaction.hpp"

void create_table_from_transaction_block(lua_State* L, const uc_tb* block)
{
    lua_createtable(L, 0, 3);

    lua_pushinteger(L, static_cast<lua_Integer>(block->pc));
    lua_setfield(L, -1, "pc");
    lua_pushinteger(L, static_cast<lua_Integer>(block->icount));
    lua_setfield(L, -1, "icount");
    lua_pushinteger(L, static_cast<lua_Integer>(block->size));
    lua_setfield(L, -1, "size");
}

#endif // UC_API_MAJOR
