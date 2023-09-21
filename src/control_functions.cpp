#include <stdexcept>
#include <unicorn/unicorn.h>

#include "unicornlua/lua.hpp"

[[noreturn]] int ul_crash_unsupported_operation(lua_State* L)
{
    (void)L;
    throw std::runtime_error(
        "Functionality not supported in this version of Unicorn.");
}

#if UC_API_MAJOR >= 2
#include <cstdint>
#include <memory>

#include "unicornlua/control_functions.hpp"
#include "unicornlua/engine.hpp"
#include "unicornlua/transaction.hpp"
#include "unicornlua/utils.hpp"

int ul_ctl_get_exits(lua_State* L)
{
    UCLuaEngine* engine = ul_toluaengine(L, 1);
    uc_engine* handle = engine->get_handle();
    size_t count;

    // Determine how many exit points we have registered.
    uc_err error = uc_ctl_get_exits_cnt(handle, &count);
    if (error != UC_ERR_OK)
        ul_crash_on_error(L, error);

    // Get the exit points.
    std::unique_ptr<uint64_t[]> array(new uint64_t[count]);
    error = uc_ctl_get_exits(handle, array.get(), count);
    if (error != UC_ERR_OK)
        ul_crash_on_error(L, error);

    // Put the exit points into a Lua table.
    lua_createtable(L, static_cast<int>(count), 0);
    for (size_t i = 0; i < count; i++) {
        lua_pushinteger(L, static_cast<lua_Integer>(array.get()[i]));
        lua_seti(L, -1, static_cast<int>(i));
    }

    return 1;
}

int ul_ctl_request_cache(lua_State* L)
{
    UCLuaEngine* engine = ul_toluaengine(L, 1);
    uc_engine* handle = engine->get_handle();

    auto address = static_cast<uint64_t>(lua_tointeger(L, 2));
    uc_tb tblock;

    uc_err error = uc_ctl_request_cache(handle, address, &tblock);
    if (error != UC_ERR_OK)
        ul_crash_on_error(L, error);

    create_table_from_transaction_block(L, &tblock);
    return 1;
}

int ul_ctl_set_exits(lua_State* L)
{
    UCLuaEngine* engine = ul_toluaengine(L, 1);
    uc_engine* handle = engine->get_handle();

    auto n_entries = static_cast<size_t>(luaL_len(L, 2));
    if (n_entries < 1)
        return 0;

    std::unique_ptr<uint64_t[]> entries(new uint64_t[n_entries]);

    // The table argument lists all the exit points. Iterate over these, putting
    // them into the array we're about to pass Unicorn.
    for (int i = 0; i < static_cast<int>(n_entries); i++) {
        lua_geti(L, 2, i + 1);
        entries.get()[i] = static_cast<uint64_t>(lua_tointeger(L, -1));
        lua_pop(L, 1);
    }

    uc_err error = uc_ctl_set_exits(handle, entries.get(), n_entries);
    if (error != UC_ERR_OK)
        ul_crash_on_error(L, error);
    return 0;
}
#endif // UC_API_MAJOR >= 2
