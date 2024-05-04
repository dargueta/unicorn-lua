#pragma once

#include "lua.hpp"
#include <cstdint>


// Lua 5.1 has lua_Integer but doesn't define LUA_MAXINTEGER. We know from the docs that
// lua_Integer is hard-coded to ptrdiff_t, so we can get away defining these like so:s
#ifndef LUA_MAXINTEGER
#   define LUA_MAXINTEGER PTRDIFF_MAX
#   define LUA_MININTEGER PTRDIFF_MIN
#   define LUA_MAXUNSIGNED PTRDIFF_MAX
    typedef lua_Number lua_Unsigned;
#endif

// Because Lua integers are always signed, we can't assume lua_Integer can hold
// lua_Unsigned. (That will pretty much only be the case for a system with a
// one's-complement integer representation.)

#if LUA_MAXINTEGER >= INT_LEAST64_MAX
    // Lua integers are at least 64 bits.
#   define ul_lua_int32_t_equiv_type lua_Integer
#   define ul_lua_uint32_t_equiv_type lua_Unsigned
#   define ul_lua_int64_t_equiv_type lua_Integer
#   define ul_push_int32_t_equiv(L, i) lua_pushinteger((L), (lua_Integer)(i))
#   define ul_push_uint32_t_equiv(L, i) lua_pushinteger((L), (lua_Integer)(i))
#   define ul_push_int64_t_equiv(L, i) lua_pushinteger((L), (lua_Integer)(i))
#   define ul_to_int32_t_equiv(L, i) lua_tointeger((L), (i))
#   define ul_to_uint32_t_equiv(L, i) lua_tointeger((L), (i))
#   define ul_to_int64_t_equiv(L, i) lua_tointeger((L), (i))
#   if LUA_MAXINTEGER >= LUA_MAXUNSIGNED
#      define ul_lua_uint64_t_equiv_type lua_Integer
#      define ul_push_uint64_t_equiv(L, i) lua_pushinteger((L), (lua_Integer)(i))
#      define ul_to_uint64_t_equiv(L, i) lua_tointeger((L), (i))
#   else
#      define ul_lua_uint64_t_equiv_type lua_Number
#      define ul_push_uint64_t_equiv(L, i) lua_pushnumber((L), (lua_Number)(i))
#      define ul_to_uint64_t_equiv(L, i) lua_tonumber((L), (i))
#   endif
#elif LUA_MAXINTEGER >= INT_LEAST32_MAX
    // Lua integers are at least 32 bits but less than 64.
#   define ul_lua_int32_t_equiv_type lua_Integer
#   define ul_lua_int64_t_equiv_type lua_Number
#   define ul_lua_uint64_t_equiv_type lua_Number
#   define ul_push_int32_t_equiv(L, i) lua_pushinteger((L), (lua_Integer)(i))
#   define ul_push_int64_t_equiv(L, i) lua_pushnumber((L), (lua_Number)(i))
#   define ul_push_uint64_t_equiv(L, i) lua_pushnumber((L), (lua_Number)(i))
#   define ul_to_int32_t_equiv(L, i) lua_tointeger((L), (i))
#   define ul_to_int64_t_equiv(L, i) lua_tonumber((L), (i))
#   define ul_to_uint64_t_equiv(L, i) lua_tonumber((L), (i))

#   if LUA_MAXINTEGER >= LUA_MAXUNSIGNED
#      define ul_lua_uint32_t_equiv_type lua_Integer
#      define ul_push_uint32_t_equiv(L, i) lua_pushinteger((L), (lua_Integer)(i))
#      define ul_to_uint32_t_equiv(L, i) lua_tointeger((L), (i))
#   else
#      define ul_lua_uint32_t_equiv_type lua_Number
#      define ul_push_uint32_t_equiv(L, i) lua_pushnumber((L), (lua_Number)(i))
#      define ul_to_uint32_t_equiv(L, i) lua_tonumber((L), (i))
#   endif
#else
    // We're on a system where `int` is 16 bits and LUA_INT_TYPE is set to LUA_INT_INT.
    // It's unclear if Unicorn can even compile on such a system but we need to be able
    // to handle this situation just in case.
#   define ul_lua_int32_t_equiv_type lua_Number
#   define ul_lua_uint32_t_equiv_type lua_Number
#   define ul_lua_int64_t_equiv_type lua_Number
#   define ul_lua_uint64_t_equiv_type lua_Number
#   define ul_push_int32_t_equiv(L, i) lua_pushnumber((L), (lua_Number)(i))
#   define ul_push_uint32_t_equiv(L, i) lua_pushnumber((L), (lua_Number)(i))
#   define ul_push_int64_t_equiv(L, i) lua_pushnumber((L), (lua_Number)(i))
#   define ul_push_uint64_t_equiv(L, i) lua_pushnumber((L), (lua_Number)(i))
#   define ul_to_int32_t_equiv(L, i) lua_tonumber((L), (i))
#   define ul_to_uint32_t_equiv(L, i) lua_tonumber((L), (i))
#   define ul_to_int64_t_equiv(L, i) lua_tonumber((L), (i))
#   define ul_to_uint64_t_equiv(L, i) lua_tonumber((L), (i))
#endif

#   if LUA_MAXINTEGER >= SIZE_MAX
       // A regular Lua integer can safely hold a size_t. This will only ever be the case
       // on systems where a size_t cannot hold a pointer, e.g. a 64-bit system with a
       // 32-bit size_t. This is uncommon but does exist.
#      define ul_lua_size_t_equiv_type lua_Unsigned
#      define ul_push_size_t_equiv(L, i) lua_pushinteger((L), (lua_Integer)(i))
#      define ul_to_size_t_equiv(L, i) lua_tointeger((L), (i))
#   else
#      define ul_lua_size_t_equiv_type lua_Number
#      define ul_push_size_t_equiv(L, i) lua_pushnumber((L), (lua_Number)(i))
#      define ul_to_size_t_equiv(L, i) lua_tonumber((L), (i))
#   endif

#define ul_lua_int_equiv_type lua_Integer
#define ul_push_int_equiv(L, i) lua_pushinteger((L), (lua_Integer)(i))
#define ul_to_int_equiv(L, i) lua_tointeger((L), (i))
