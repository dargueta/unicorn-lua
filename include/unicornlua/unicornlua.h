/**
 * The primary Unicorn Lua header needed by all C code using the library.
 *
 * @file unicornlua.h
 */

#ifndef INCLUDE_UNICORNLUA_UNICORNLUA_H_
#define INCLUDE_UNICORNLUA_UNICORNLUA_H_

#include <unicorn/unicorn.h>

#include "unicornlua/compat.h"
#include "unicornlua/lua.h"


#if UC_VERSION_MAJOR != 1
    #error "Library must be compiled against version 1.x of Unicorn."
#endif


int ul_version(lua_State *L);

int ul_arch_supported(lua_State *L);

int ul_open(lua_State *L);

//int ul_strerror(lua_State *L);

int ul_free(lua_State *L);


#endif  /* INCLUDE_UNICORNLUA_UNICORNLUA_H_ */
