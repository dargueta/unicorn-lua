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

#pragma once

#include "lua.hpp"
#include <climits>
#include <cstdint>

// We know lua_Integer is always at least 32 bits, so we don't need any checks here.
#define ul_lua_int32_t_equiv_type lua_Integer
#define ul_push_int32_t_equiv(L, i) lua_pushinteger((L), static_cast<lua_Integer>(i))
#define ul_to_int32_t_equiv(L, i) static_cast<int32_t>(lua_tointeger((L), (i)))

#define ul_lua_int_equiv_type lua_Integer
#define ul_push_int_equiv(L, i) lua_pushinteger((L), static_cast<lua_Integer>(i))
#define ul_to_int_equiv(L, i) static_cast<int>(lua_tointeger((L), (i)))

/*
 * The following are default configurations and definitions for Lua integers. Note that
 * for Lua 5.1 and 5.2, `lua_Integer` can be redefined to any type. In 5.3+, it must be
 * one of `long long`, `long`, or `int`; `ptrdiff_t` is no longer an option.
 *
 * Lua 5.1:
 *     - lua_Integer: ptrdiff_t
 *     - lua_Unsigned: -
 *     - Defines LUA_MAXINTEGER: No
 *     - Defines LUA_MAXUNSIGNED: -
 * Lua 5.2:
 *     - lua_Integer: ptrdiff_t
 *     - lua_Unsigned: `int` or `long`, whichever is smallest and at least 32 bits.
 *     - Defines LUA_MAXINTEGER: No
 *     - Defines LUA_MAXUNSIGNED: No
 * Lua 5.3+:
 *     - lua_Integer:
 *           - 32-bit builds: `int` or `long`, whichever is smallest and at least 32 bits.
 *           - 64-bit builds: long long
 *     - lua_Unsigned: unsigned of lua_Integer type
 *     - Defines LUA_MAXINTEGER: Yes
 *     - Defines LUA_MAXUNSIGNED: Yes
 */
#ifdef LUA_MAXINTEGER
#    if LUA_MAXINTEGER >= UINT32_MAX
#        define ul_lua_uint32_t_equiv_type lua_Unsigned
#        define ul_push_uint32_t_equiv(L, i)                                             \
            lua_pushinteger((L), static_cast<lua_Integer>(i))
#        define ul_to_uint32_t_equiv(L, i) static_cast<uint32_t>(lua_tointeger((L), (i)))
#    endif

#    if LUA_MAXINTEGER >= INT64_MAX
#        define ul_lua_int64_t_equiv_type lua_Integer
#        define ul_push_int64_t_equiv(L, i)                                              \
            lua_pushinteger((L), static_cast<lua_Integer>(i))
#        define ul_to_int64_t_equiv(L, i) static_cast<int64_t>(lua_tointeger((L), (i)))
#    endif

#    if LUA_MAXINTEGER >= UINT64_MAX
#        define ul_lua_uint64_t_equiv_type lua_Integer
#        define ul_push_uint64_t_equiv(L, i)                                             \
            lua_pushinteger((L), static_cast<lua_Integer>(i))
#        define ul_to_uint64_t_equiv(L, i) lstatic_cast<uint64_t>(lua_tointeger((L), (i)))
#    endif

#    if LUA_MAXINTEGER >= SIZE_MAX
// A regular Lua integer can safely hold a size_t. This will only ever be the case on
// systems where size_t cannot hold a pointer, e.g. a 64-bit system with a 32-bit size_t.
// This is uncommon but does exist.
#        define ul_lua_size_t_equiv_type lua_Unsigned
#        define ul_push_size_t_equiv(L, i)                                               \
            lua_pushinteger((L), static_cast<lua_Integer>(i))
#        define ul_to_size_t_equiv(L, i) static_cast<size_t>(lua_tointeger((L), (i)))
#    endif
#endif // LUA_MAXINTEGER

// Lua 5.1 and 5.2 use ptrdiff_t as their default integer type. On a 64-bit system this
// *might* be able to hold a 32-bit unsigned integer. Technically, ptrdiff_t only needs to
// be able to hold pointer arithmetic between pointers in the same array. If on a 64-bit
// system malloc() will only let you allocate 4GiB, ptrdiff_t might be a 32-bit type.
//
// Of course, this assumes that whoever built Lua didn't change it to a type smaller than
// ptrdiff_t.
#if (LUA_VERSION_NUM == 501 || LUA_VERSION_NUM == 502) && (PTRDIFF_MAX >= UINT32_MAX)
#    define ul_lua_uint32_t_equiv_type lua_Integer
#    define ul_push_uint32_t_equiv(L, i) lua_pushinteger((L), static_cast<lua_Integer>(i))
#    define ul_to_uint32_t_equiv(L, i) static_cast<uint32_t>(lua_tointeger((L), (i)))
#endif

// ---------------------------------------------------------------------------------------
// Fallbacks for anything not defined as an integer

#ifndef ul_lua_uint32_t_equiv_type
#    define ul_lua_uint32_t_equiv_type lua_Number
#    define ul_push_uint32_t_equiv(L, i) lua_pushnumber((L), static_cast<lua_Number>(i))
#    define ul_to_uint32_t_equiv(L, i) static_cast<uint32_t>(lua_tonumber((L), (i)))
#endif // ul_lua_uint32_t_equiv_type

#ifndef ul_lua_int64_t_equiv_type
#    define ul_lua_int64_t_equiv_type lua_Number
#    define ul_push_int64_t_equiv(L, i) lua_pushnumber((L), static_cast<lua_Number>(i))
#    define ul_to_int64_t_equiv(L, i) static_cast<int64_t>(lua_tonumber((L), (i)))
#endif // ul_lua_int64_t_equiv_type

#ifndef ul_lua_uint64_t_equiv_type
#    define ul_lua_uint64_t_equiv_type lua_Number
#    define ul_push_uint64_t_equiv(L, i) lua_pushnumber((L), static_cast<lua_Number>(i))
#    define ul_to_uint64_t_equiv(L, i) static_cast<uint64_t>(lua_tonumber((L), (i)))
#endif // ul_lua_uint64_t_equiv_type

#ifndef ul_lua_size_t_equiv_type
#    define ul_lua_size_t_equiv_type lua_Number
#    define ul_push_size_t_equiv(L, i) lua_pushnumber((L), static_cast<lua_Number>(i))
#    define ul_to_size_t_equiv(L, i) static_cast<size_t>(lua_tonumber((L), (i)))
#endif // ul_lua_size_t_equiv_type
