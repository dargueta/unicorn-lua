#include <memory>

#include <unicorn/unicorn.h>

#include "unicornlua/compat.h"
#include "unicornlua/engine.h"
#include "unicornlua/lua.h"
#include "unicornlua/utils.h"

int ul_mem_write(lua_State* L)
{
    size_t length;

    uc_engine* engine = ul_toengine(L, 1);
    auto address = static_cast<uint64_t>(luaL_checkinteger(L, 2));
    const void* data = luaL_checklstring(L, 3, &length);

    uc_err error = uc_mem_write(engine, address, data, length);
    if (error != UC_ERR_OK)
        return ul_crash_on_error(L, error);
    return 0;
}

int ul_mem_read(lua_State* L)
{
    uc_engine* engine = ul_toengine(L, 1);
    auto address = static_cast<uint64_t>(luaL_checkinteger(L, 2));
    auto length = static_cast<size_t>(luaL_checkinteger(L, 3));

    std::unique_ptr<char[]> data(new char[length]);
    uc_err error = uc_mem_read(engine, address, data.get(), length);
    if (error != UC_ERR_OK)
        return ul_crash_on_error(L, error);

    lua_pushlstring(L, data.get(), length);
    return 1;
}

int ul_mem_map(lua_State* L)
{
    uc_engine* engine = ul_toengine(L, 1);
    auto address = static_cast<uint64_t>(luaL_checkinteger(L, 2));
    auto size = static_cast<size_t>(luaL_checkinteger(L, 3));
    auto perms = static_cast<uint32_t>(luaL_optinteger(L, 4, UC_PROT_ALL));

    uc_err error = uc_mem_map(engine, address, size, perms);
    if (error != UC_ERR_OK)
        return ul_crash_on_error(L, error);
    return 0;
}

int ul_mem_unmap(lua_State* L)
{
    uc_engine* engine = ul_toengine(L, 1);
    auto address = static_cast<uint64_t>(luaL_checkinteger(L, 2));
    auto size = static_cast<size_t>(luaL_checkinteger(L, 3));

    uc_err error = uc_mem_unmap(engine, address, size);
    if (error != UC_ERR_OK)
        return ul_crash_on_error(L, error);
    return 0;
}

int ul_mem_protect(lua_State* L)
{
    uc_engine* engine = ul_toengine(L, 1);
    auto address = static_cast<uint64_t>(luaL_checkinteger(L, 2));
    auto size = static_cast<size_t>(luaL_checkinteger(L, 3));
    auto perms = static_cast<uint32_t>(luaL_checkinteger(L, 4));

    uc_err error = uc_mem_protect(engine, address, size, perms);
    if (error != UC_ERR_OK)
        return ul_crash_on_error(L, error);
    return 0;
}

int ul_mem_regions(lua_State* L)
{
    uint32_t n_regions;

    uc_engine* engine = ul_toengine(L, 1);
    uc_mem_region* regions = nullptr;
    n_regions = 0;

    uc_err error = uc_mem_regions(engine, &regions, &n_regions);
    if (error != UC_ERR_OK)
        return ul_crash_on_error(L, error);

    lua_createtable(L, static_cast<int>(n_regions), 0);
    for (uint32_t i = 0; i < n_regions; ++i) {
        lua_createtable(L, 0, 3);

        lua_pushinteger(L, static_cast<lua_Integer>(regions[i].begin));
        lua_setfield(L, -2, "begins");

        lua_pushinteger(L, static_cast<lua_Integer>(regions[i].end));
        lua_setfield(L, -2, "ends");

        lua_pushinteger(L, regions[i].perms);
        lua_setfield(L, -2, "perms");

        /* Append this region descriptor to the table we're going to return. */
        lua_seti(L, -2, static_cast<lua_Integer>(i) + 1);
    }

    uc_free(regions);
    return 1;
}
