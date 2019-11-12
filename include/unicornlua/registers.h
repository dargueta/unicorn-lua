/**
 * Lua bindings for Unicorn register operations.
 *
 * @file registers.h
 */

#ifndef INCLUDE_UNICORNLUA_REGISTERS_H_
#define INCLUDE_UNICORNLUA_REGISTERS_H_

#include "unicornlua/lua.h"


/**
 * Define a buffer large enough to hold the largest registers available.
 *
 * We need 64 bytes to be able to hold a 512-bit ZMM register. For now, only the
 * low 32 or 64 bits are accessible to Lua. Eventually we'll figure out how to
 * use the rest.
*/
typedef char register_buffer_type[64];


/**
 * Write to an architecture register.
 */
int ul_reg_write(lua_State *L);
int ul_reg_read(lua_State *L);
int ul_reg_write_batch(lua_State *L);
int ul_reg_read_batch(lua_State *L);

#endif  /* INCLUDE_UNICORNLUA_REGISTERS_H_ */
