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

/**
 * Determine if the given architecture is supported on this platform.
 *
 * Usage:
 *
 *      unicorn.arch_supported(unicorn.UC_ARCH_ARM)
 */
int ul_arch_supported(lua_State *L);

int ul_close(lua_State *L);
int ul_context_restore(lua_State *L);
int ul_context_save(lua_State *L);
int ul_emu_start(lua_State *L);
int ul_emu_stop(lua_State *L);
int ul_errno(lua_State *L);

/**
 * Release resources used by an engine or context.
 *
 * This function is not directly exposed to Lua code. Rather, it's set as the
 * garbage collection metamethod.
 */
int ul_free(lua_State *L);

int ul_hook_add(lua_State *L);
int ul_hook_del(lua_State *L);
int ul_mem_map(lua_State *L);
int ul_mem_protect(lua_State *L);
int ul_mem_read(lua_State *L);
int ul_mem_regions(lua_State *L);
int ul_mem_unmap(lua_State *L);
int ul_mem_write(lua_State *L);
int ul_open(lua_State *L);
int ul_query(lua_State *L);
int ul_reg_read(lua_State *L);
int ul_reg_read_batch(lua_State *L);
int ul_reg_write(lua_State *L);
int ul_reg_write_batch(lua_State *L);

/**
 * Get a formatted error message from the given Unicorn error code.
 *
 * Usage:
 *
 *     local message = unicorn.strerror(123)
 */
int ul_strerror(lua_State *L);


/**
 * Get the major and minor versions numbers of the Unicorn library.
 *
 * Usage:
 *
 *      local major, minor = unicorn.version()
 */
int ul_version(lua_State *L);

#endif  /* INCLUDE_UNICORNLUA_UNICORNLUA_H_ */
