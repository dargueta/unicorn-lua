#include <lua.h>
#include <unicorn/unicorn.h>

#pragma once

typedef struct
{
    uc_engine *engine;
    uc_hook_type hook_type;
    uint64_t start_address;
    uint64_t end_address;
    int extra_data_ref;
    int callback_ref;
    void *c_callback_fn;
    uc_hook hook_handle;
    lua_State *L;
} ULHook;

int ul_hook_del(lua_State *L);
int ul_create_interrupt_hook(lua_State *L);
int ul_create_memory_access_hook(lua_State *L);
int ul_create_invalid_mem_access_hook(lua_State *L);
int ul_create_port_in_hook(lua_State *L);
int ul_create_port_out_hook(lua_State *L);
int ul_create_arm64_sys_hook(lua_State *L);
int ul_create_invalid_instruction_hook(lua_State *L);
int ul_create_cpuid_hook(lua_State *L);
int ul_create_generic_hook_with_no_arguments(lua_State *L);
int ul_create_edge_generated_hook(lua_State *L);

void ulinternal_hook_callback__no_arguments(uc_engine *engine, void *userdata);
