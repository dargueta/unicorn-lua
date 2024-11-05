#include "unicornlua/control_functions.h"
#include "unicornlua/utils.h"
#include <errno.h>
#include <lua.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unicorn/unicorn.h>

int ul_ctl_get_exits(lua_State *L)
{
    uc_engine *engine = (uc_engine *)lua_topointer(L, 1);

    size_t n_exits;
    uc_err error = uc_ctl_get_exits_cnt(engine, &n_exits);
    ulinternal_crash_if_failed(L, error, "ctl_get_exits failed to get exit count.");

    uint64_t *exits = (uint64_t *)malloc(sizeof(*exits) * n_exits);
    if (exits == NULL)
    {
        ulinternal_crash(L, "Failed to allocate space for %u exit addresses: %s", n_exits,
                         strerror(errno));
    }

    error = uc_ctl_get_exits(engine, exits, n_exits);
    ulinternal_crash_if_failed(L, error, "ctl_get_exits() API call failed.");

    lua_createtable(L, (int)n_exits, 0);
    for (int i = 0; i < (int)n_exits; i++)
    {
#if LUA_VERSION_NUM >= 502
        lua_pushinteger(L, (lua_Integer)exits[i]);
        lua_rawseti(L, i, -2);
#else
        lua_pushinteger(L, (lua_Integer)i);
        lua_pushinteger(L, (lua_Integer)exits[i]);
        lua_rawset(L, -3);
#endif
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
    ulinternal_crash_not_implemented(L);
}
