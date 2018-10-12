/**
 * @file unicornlua.h
 */

#ifndef INCLUDE_UNICORNLUA_UNICORNLUA_H_
#define INCLUDE_UNICORNLUA_UNICORNLUA_H_

#include <lauxlib.h>
#include <lua.h>

int uc_lua__arch_supported(lua_State *L);
int uc_lua__close(lua_State *L);
int uc_lua__context_alloc(lua_State *L);
int uc_lua__context_restore(lua_State *L);
int uc_lua__context_save(lua_State *L);
int uc_lua__context_update(lua_State *L);
int uc_lua__emu_start(lua_State *L);
int uc_lua__emu_stop(lua_State *L);
int uc_lua__errno(lua_State *L);
int uc_lua__free(lua_State *L);
int uc_lua__hook_add(lua_State *L);
int uc_lua__hook_del(lua_State *L);
int uc_lua__mem_map(lua_State *L);
int uc_lua__mem_protect(lua_State *L);
int uc_lua__mem_read(lua_State *L);
int uc_lua__mem_regions(lua_State *L);
int uc_lua__mem_unmap(lua_State *L);
int uc_lua__mem_write(lua_State *L);
int uc_lua__open(lua_State *L);
int uc_lua__query(lua_State *L);
int uc_lua__reg_read(lua_State *L);
int uc_lua__reg_read_batch(lua_State *L);
int uc_lua__reg_write(lua_State *L);
int uc_lua__reg_write_batch(lua_State *L);
int uc_lua__strerror(lua_State *L);
int uc_lua__version(lua_State *L);

#endif  /* INCLUDE_UNICORNLUA_UNICORNLUA_H_ */
