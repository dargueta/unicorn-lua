#include "unicornlua/control_functions.h"
#include "unicornlua/utils.h"
#include <errno.h>
#include <inttypes.h>
#include <lua.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unicorn/unicorn.h>

/// @submodule unicorn_c_

#if UC_VERSION_MAJOR >= 2
int ul_ctl_get_exits(lua_State *L)
{
    uc_engine *engine = (uc_engine *)lua_topointer(L, 1);

    size_t n_exits;
    uc_err error = uc_ctl_get_exits_cnt(engine, &n_exits);
    ulinternal_crash_if_failed(L, error, "ctl_get_exits failed to get exit count.");

    uint64_t *exits = (uint64_t *)malloc(sizeof(*exits) * n_exits);
    if (exits == NULL)
    {
        ulinternal_crash(L, "Failed to allocate space for %zu exit addresses: %s",
                         n_exits, strerror(errno));
    }

    error = uc_ctl_get_exits(engine, exits, n_exits);
    ulinternal_crash_if_failed(L, error, "ctl_get_exits() API call failed.");

    lua_createtable(L, (int)n_exits, 0);
    for (size_t i = 0; i < n_exits; i++)
    {
        lua_pushinteger(L, (lua_Integer)exits[i]);
        lua_rawseti(L, (int)(i + 1), -2);
    }

    free(exits);
    return 1;
}

int ul_ctl_set_exits(lua_State *L)
{
    ulinternal_crash_not_implemented(L);
}

int ul_ctl_request_cache(lua_State *L)
{
    uc_tb translation_block;

    uc_engine *engine = (uc_engine *)lua_topointer(L, 1);
    uint64_t address = (uint64_t)luaL_checkinteger(L, 2);

    uc_err error = uc_ctl_request_cache(engine, address, &translation_block);
    ulinternal_crash_if_failed(
        L, error, "Failed to get translation block at address 0x%08" PRIX64, address);

    /* Create a table representing this struct. */
    lua_createtable(L, 0, 3);
    lua_pushinteger(L, (lua_Integer)translation_block.pc);
    lua_setfield(L, -2, "pc");
    lua_pushinteger(L, (lua_Integer)translation_block.icount);
    lua_setfield(L, -2, "icount");
    lua_pushinteger(L, (lua_Integer)translation_block.size);
    lua_setfield(L, -2, "size");

    return 1;
}
#endif
