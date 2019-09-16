#include <string.h>

#include <unicorn/unicorn.h>

#include "unicornlua/compat.h"
#include "unicornlua/engine.h"
#include "unicornlua/lua.h"
#include "unicornlua/utils.h"


int ul_reg_write(lua_State *L) {
    uc_engine *engine = ul_toengine(L, 1);
    int register_id = luaL_checkinteger(L, 2);
    lua_Unsigned value = (lua_Unsigned)luaL_checkinteger(L, 3);

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

    int *registers = new int[n_registers];
    lua_Unsigned *values = new lua_Unsigned[n_registers];
    void **p_values = new void *[n_registers];

    /* Iterate through the register/value pairs and put them in the corresponding
     * array positions. */
    lua_pushnil(L);
    for (int i = 0; lua_next(L, 2) != 0; ++i) {
        registers[i] = luaL_checkinteger(L, -2);
        values[i] = (lua_Unsigned)luaL_checkinteger(L, -1);
        lua_pop(L, 1);
    }

    /* p_values is an array of pointers to the values we want to set, as required
     * by the library. Set the pointers here. */
    for (int i = 0; i < n_registers; ++i)
        p_values[i] = &values[i];

    uc_err error = uc_reg_write_batch(engine, registers, p_values, n_registers);
    delete[] registers;
    delete[] values;
    delete[] p_values;

    if (error != UC_ERR_OK)
        return ul_crash_on_error(L, error);
    return 0;
}


int ul_reg_read_batch(lua_State *L) {
    uc_engine *engine = ul_toengine(L, 1);
    int n_registers = lua_gettop(L) - 1;

    int *registers = new int[n_registers];
    lua_Integer *values = new lua_Integer[n_registers];
    void **p_values = new void *[n_registers];

    for (int i = 0; i < n_registers; ++i) {
        registers[i] = (int)lua_tointeger(L, i + 2);
        p_values[i] = &values[i];
    }

    memset(values, 0, n_registers * sizeof(*values));
    uc_err error = uc_reg_read_batch(engine, registers, p_values, n_registers);

    if (error != UC_ERR_OK) {
        delete[] registers;
        delete[] values;
        delete[] p_values;
        return ul_crash_on_error(L, error);
    }

    for (int i = 0; i < n_registers; ++i)
        lua_pushinteger(L, values[i]);

    delete[] registers;
    delete[] values;
    delete[] p_values;
    return n_registers;
}
