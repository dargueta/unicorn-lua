#include <lauxlib.h>
#include <lua.h>
#include <unicorn/unicorn.h>

#include "unicornlua/numbers.h"
#include "unicornlua/utils.h"


int uc_lua__mem_write(lua_State *L) {
    uc_engine *engine;
    lua_Unsigned address;
    const void *data;
    size_t length;
    int error;

    engine = uc_lua__toengine(L, 1);
    address = uc_lua__cast_unsigned(L, 2);
    data = (const void *)luaL_checklstring(L, 3, &length);

    error = uc_mem_write(engine, address, data, length);
    if (error != UC_ERR_OK)
        return uc_lua__crash_on_error(L, error);

    return 0;
}


int uc_lua__mem_read(lua_State *L) {
    uc_engine *engine;
    lua_Unsigned address, length;
    void *data;
    int error;

    engine = uc_lua__toengine(L, 1);
    address = uc_lua__cast_unsigned(L, 2);
    length = uc_lua__cast_unsigned(L, 3);

    data = uc_lua__realloc(L, NULL, length);

    error = uc_mem_read(engine, address, data, (size_t)length);
    if (error != UC_ERR_OK) {
        free(data);
        return uc_lua__crash_on_error(L, error);
    }

    lua_pushlstring(L, data, length);
    return 1;
}


int uc_lua__mem_map(lua_State *L) {
    uc_engine *engine;
    lua_Unsigned address, size, perms;
    int error;

    engine = uc_lua__toengine(L, 1);
    address = uc_lua__cast_unsigned(L, 2);
    size = uc_lua__cast_unsigned(L, 3);
    perms = (lua_Unsigned)luaL_optinteger(L, 4, UC_PROT_ALL);

    error = uc_mem_map(engine, address, size, perms);
    if (error != UC_ERR_OK)
        return uc_lua__crash_on_error(L, error);
    return 0;
}


int uc_lua__mem_unmap(lua_State *L) {
    uc_engine *engine;
    lua_Unsigned address, size;
    int error;

    engine = uc_lua__toengine(L, 1);
    address = uc_lua__cast_unsigned(L, 2);
    size = uc_lua__cast_unsigned(L, 3);

    error = uc_mem_unmap(engine, address, size);
    if (error != UC_ERR_OK)
        return uc_lua__crash_on_error(L, error);
    return 0;
}

int uc_lua__mem_protect(lua_State *L) {
    uc_engine *engine;
    lua_Unsigned address, size, perms;
    int error;

    engine = uc_lua__toengine(L, 1);
    address = uc_lua__cast_unsigned(L, 2);
    size = uc_lua__cast_unsigned(L, 3);
    perms = uc_lua__cast_unsigned(L, 4);

    error = uc_mem_protect(engine, address, size, perms);
    if (error != UC_ERR_OK)
        return uc_lua__crash_on_error(L, error);
    return 0;
}

int uc_lua__mem_regions(lua_State *L) {
    uc_engine *engine;
    uc_mem_region *regions;
    uint32_t n_regions, i;
    int error;

    engine = uc_lua__toengine(L, 1);
    regions = NULL;
    n_regions = 0;

    error = uc_mem_regions(engine, &regions, &n_regions);
    if (error != UC_ERR_OK)
        return uc_lua__crash_on_error(L, error);

    lua_createtable(L, n_regions, 0);

    for (i = 0; i < n_regions; ++i) {
        lua_createtable(L, 0, 3);

        lua_pushinteger(L, regions[i].begin);
        lua_setfield(L, -1, "begin");

        lua_pushinteger(L, regions[i].end);
        lua_setfield(L, -1, "end");

        lua_pushinteger(L, regions[i].perms);
        lua_setfield(L, -1, "perms");

        #if LUA_VERSION_NUM >= 503
            lua_seti(L, -2, i + 1);
        #else
            /* lua_seti was added in Lua 5.3, so we need to do this manually.
             *
             * Permission entry is at TOS, array is right below it. Because
             * lua_settable expects the value on top, we need to push the key
             * and then swap the two. */
            lua_pushinteger(L, i + 1);
            lua_insert(L, lua_gettop(L) - 1);

            lua_settable(L, -2);
        #endif
    }

    uc_free(regions);
    return 1;
}
