// Copyright (C) 2017-2024 by Diego Argueta
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

#include <unicorn/unicorn.h>

#if UC_API_MAJOR >= 2
#    include "unicornlua/lua.hpp"
#    include "unicornlua/transaction.hpp"

void create_table_from_transaction_block(lua_State *L, const uc_tb *block)
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
