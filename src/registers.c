#include <string.h>

#include <unicorn/unicorn.h>

#include "unicornlua/compat.h"
#include "unicornlua/engine.h"
#include "unicornlua/lua.h"
#include "unicornlua/utils.h"


int ul_reg_write(lua_State *L) {
    uc_engine *engine;
    int register_id, error;
    lua_Unsigned value;

    engine = ul_toengine(L, 1);
    register_id = luaL_checkinteger(L, 2);
    value = (lua_Unsigned)luaL_checkinteger(L, 3);

    error = uc_reg_write(engine, register_id, &value);
    if (error != UC_ERR_OK)
        return ul_crash_on_error(L, error);

    return 0;
}


int ul_reg_read(lua_State *L) {
    uc_engine *engine;
    int register_id, error;
    lua_Unsigned value = 0;

    engine = ul_toengine(L, 1);
    register_id = luaL_checkinteger(L, 2);

    error = uc_reg_read(engine, register_id, &value);
    if (error != UC_ERR_OK)
        return ul_crash_on_error(L, error);

    lua_pushinteger(L, value);
    return 1;
}


int ul_reg_write_batch(lua_State *L) {
    uc_engine *engine;
    int n_registers, error, *registers, i;
    lua_Unsigned *values;
    void **p_values;

    engine = ul_toengine(L, 1);

    /* Second argument will be a table with key-value pairs, the keys being the
     * registers to write to and the values being the values to write to the
     * corresponding registers. */

    /* Count the number of items in the table so we can allocate the buffers of
     * the right size. */
    lua_pushnil(L);
    for (n_registers = 0; lua_next(L, 2) != 0; ++n_registers)
        lua_pop(L, 1);

    registers = (int *)malloc(n_registers * sizeof(*registers));
    values = (lua_Unsigned *)malloc(n_registers * sizeof(*values));

    lua_pushnil(L);
    for (i = 0; lua_next(L, 2) != 0; ++i) {
        registers[i] = luaL_checkinteger(L, -2);
        values[i] = (lua_Unsigned)luaL_checkinteger(L, -1);
        lua_pop(L, 1);
    }

    p_values = (void **)malloc(n_registers * sizeof(*p_values));
    for (i = 0; i < n_registers; ++i)
        p_values[i] = &values[i];

    error = uc_reg_write_batch(engine, registers, p_values, n_registers);

    free(registers);
    free(values);
    free(p_values);

    if (error != UC_ERR_OK)
        return ul_crash_on_error(L, error);
    return 0;
}


int ul_reg_read_batch(lua_State *L) {
    uc_engine *engine;
    int n_registers, i, error, *registers;
    lua_Integer *values;
    void **p_values;

    engine = ul_toengine(L, 1);
    n_registers = lua_gettop(L) - 1;

    registers = (int *)malloc(n_registers * sizeof(*registers));
    values = (lua_Integer *)malloc(n_registers * sizeof(*values));
    p_values = (void **)malloc(n_registers * sizeof(*p_values));

    for (i = 0; i < n_registers; ++i) {
        registers[i] = (int)lua_tointeger(L, i + 2);
        p_values[i] = &values[i];
    }

    memset(values, 0, n_registers * sizeof(*values));
    error = uc_reg_read_batch(engine, registers, p_values, n_registers);

    if (error != UC_ERR_OK) {
        free(registers);
        free(values);
        free(p_values);
        return ul_crash_on_error(L, error);
    }

    for (i = 0; i < n_registers; ++i)
        lua_pushinteger(L, values[i]);

    free(registers);
    free(values);
    free(p_values);

    return n_registers;
}
