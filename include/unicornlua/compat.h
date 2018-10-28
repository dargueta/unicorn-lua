/**
 * Compatibility shims for differences between Lua versions
 */

#ifndef INCLUDE_UNICORNLUA_COMPAT_H_
#define INCLUDE_UNICORNLUA_COMPAT_H_

#include <lua.h>

#ifndef LUA_UNSIGNED
    #define LUA_UNSIGNED    unsigned lua_Integer
    typedef unsigned lua_Integer lua_Unsigned;
#endif

#endif  /* INCLUDE_UNICORNLUA_COMPAT_H_ */
