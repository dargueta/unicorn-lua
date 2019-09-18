#include <cstring>
#include <new>

#include <unicorn/unicorn.h>

#include "unicornlua/compat.h"
#include "unicornlua/engine.h"
#include "unicornlua/lua.h"
#include "unicornlua/utils.h"


/**
 * Allocate multiple arrays, ensuring all memory is freed if any allocation fails.
 *
 * @param n_registers   The number of elements to allocate for each array.
 * @param register_ids  A pointer to an array where register IDs will be stored.
 * @param values    A pointer to an array of lua_Integer where register values go.
 * @param p_values
 *      A pointer to an array of void pointers, where each element i points to the i-th
 *      element of @a values. The function sets these for you before returning, so there's
 *      no need to initialize it.
 *
 * @return ``true`` if allocation succeeded, ``false`` otherwise.
 */
static bool alloc_register_info(
    int n_registers, int **register_ids, lua_Integer **values, void ***p_values
) {
    *register_ids = new(std::nothrow) int[n_registers];
    *values = new(std::nothrow) lua_Integer[n_registers];
    *p_values = new(std::nothrow) void *[n_registers];

    // Wait until we've allocated everything before we check the pointers. If we use
    // regular `new`, and the last allocation fails, then we leak everything we allocated
    // up to that point.
    if ((*register_ids == nullptr) || (*values == nullptr) || (*p_values == nullptr)) {
        delete[] register_ids;
        delete[] values;
        delete[] p_values;
        return false;
    }

    /* p_values is an array of pointers to the values we want to set, as required
     * by the library. Set the pointers here. */
    for (int i = 0; i < n_registers; ++i)
        (*p_values)[i] = &(*values)[i];

    return true;
}


int ul_reg_write(lua_State *L) {
    uc_engine *engine = ul_toengine(L, 1);
    int register_id = luaL_checkinteger(L, 2);
    auto value = static_cast<lua_Unsigned>(luaL_checkinteger(L, 3));

    uc_err error = uc_reg_write(engine, register_id, &value);
    if (error != UC_ERR_OK)
        return ul_crash_on_error(L, error);
    return 0;
}


int ul_reg_read(lua_State *L) {
    lua_Unsigned value = 0;
    uc_engine *engine = ul_toengine(L, 1);
    int register_id = luaL_checkinteger(L, 2);

    uc_err error = uc_reg_read(engine, register_id, &value);
    if (error != UC_ERR_OK)
        return ul_crash_on_error(L, error);

    lua_pushinteger(L, value);
    return 1;
}


int ul_reg_write_batch(lua_State *L) {
    int n_registers;

    uc_engine *engine = ul_toengine(L, 1);

    /* Second argument will be a table with key-value pairs, the keys being the
     * registers to write to and the values being the values to write to the
     * corresponding registers. */

    /* Count the number of items in the table so we can allocate the buffers of
     * the right size. We can't use luaL_len() because that doesn't tell us how
     * many keys there are in the table, only entries in the array part. */
    lua_pushnil(L);
    for (n_registers = 0; lua_next(L, 2) != 0; ++n_registers)
        lua_pop(L, 1);

    int *register_ids;
    lua_Integer *values;
    void **p_values;
    if (!alloc_register_info(n_registers, &register_ids, &values, &p_values))
        return luaL_error(L, "Out of memory.");

    /* Iterate through the register/value pairs and put them in the corresponding
     * array positions. */
    lua_pushnil(L);
    for (int i = 0; lua_next(L, 2) != 0; ++i) {
        register_ids[i] = luaL_checkinteger(L, -2);
        values[i] = (lua_Unsigned)luaL_checkinteger(L, -1);
        lua_pop(L, 1);
    }

    uc_err error = uc_reg_write_batch(engine, register_ids, p_values, n_registers);
    if (error != UC_ERR_OK)
        return ul_crash_on_error(L, error);
    return 0;
}


int ul_reg_read_batch(lua_State *L) {
    uc_engine *engine = ul_toengine(L, 1);
    int n_registers = lua_gettop(L) - 1;

    int *register_ids;
    lua_Integer *values;
    void **p_values;
    if (!alloc_register_info(n_registers, &register_ids, &values, &p_values))
        return luaL_error(L, "Out of memory.");

    for (int i = 0; i < n_registers; ++i)
        register_ids[i] = (int)lua_tointeger(L, i + 2);

    memset(values, 0, n_registers * sizeof(*values));
    uc_err error = uc_reg_read_batch(engine, register_ids, p_values, n_registers);
    if (error != UC_ERR_OK) {
        delete[] register_ids;
        delete[] values;
        delete[] p_values;
        return ul_crash_on_error(L, error);
    }

    for (int i = 0; i < n_registers; ++i)
        lua_pushinteger(L, values[i]);

    delete[] register_ids;
    delete[] values;
    delete[] p_values;
    return n_registers;
}
