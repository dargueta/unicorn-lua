#pragma once

#include <unicorn/unicorn.h>

#include "lua.hpp"

[[noreturn]] int ul_crash_immediately(lua_State* L);

#if UC_API_MAJOR >= 2
int ul_ctl_exits_disable(lua_State* L);
int ul_ctl_exits_enable(lua_State* L);
int ul_ctl_flush_tlb(lua_State* L);
int ul_ctl_get_arch(lua_State* L);
int ul_ctl_get_cpu_model(lua_State* L);
int ul_ctl_get_exits(lua_State* L);
int ul_ctl_get_exits_cnt(lua_State* L);
int ul_ctl_get_mode(lua_State* L);
int ul_ctl_get_page_size(lua_State* L);
int ul_ctl_get_timeout(lua_State* L);
int ul_ctl_remove_cache(lua_State* L);
int ul_ctl_request_cache(lua_State* L);
int ul_ctl_set_cpu_model(lua_State* L);
int ul_ctl_set_exits(lua_State* L);
int ul_ctl_set_page_size(lua_State* L);
#else
extern const lua_CFunction const ul_ctl_exits_disable;
extern const lua_CFunction const ul_ctl_exits_enable;
extern const lua_CFunction const ul_ctl_flush_tlb;
extern const lua_CFunction const ul_ctl_get_arch;
extern const lua_CFunction const ul_ctl_get_cpu_model;
extern const lua_CFunction const ul_ctl_get_exits;
extern const lua_CFunction const ul_ctl_get_exits_cnt;
extern const lua_CFunction const ul_ctl_get_mode;
extern const lua_CFunction const ul_ctl_get_page_size;
extern const lua_CFunction const ul_ctl_get_timeout;
extern const lua_CFunction const ul_ctl_remove_cache;
extern const lua_CFunction const ul_ctl_request_cache;
extern const lua_CFunction const ul_ctl_set_cpu_model;
extern const lua_CFunction const ul_ctl_set_exits;
extern const lua_CFunction const ul_ctl_set_page_size;
#endif
