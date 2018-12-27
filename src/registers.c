#include <string.h>

#include <unicorn/unicorn.h>

#include "unicornlua/compat.h"
#include "unicornlua/engine.h"
#include "unicornlua/lua.h"
#include "unicornlua/utils.h"


int uc_lua__reg_write(lua_State *L) {
    uc_engine *engine;
    int register_id, error;
    lua_Unsigned value;

    engine = uc_lua__toengine(L, 1);
    register_id = luaL_checkinteger(L, 2);
    value = (lua_Unsigned)luaL_checkinteger(L, 3);

    error = uc_reg_write(engine, register_id, &value);
    if (error != UC_ERR_OK)
        return uc_lua__crash_on_error(L, error);

    return 0;
}


int uc_lua__reg_read(lua_State *L) {
    uc_engine *engine;
    int register_id, error;
    lua_Unsigned value = 0;

    engine = uc_lua__toengine(L, 1);
    register_id = luaL_checkinteger(L, 2);

    error = uc_reg_read(engine, register_id, &value);
    if (error != UC_ERR_OK)
        return uc_lua__crash_on_error(L, error);

    lua_pushinteger(L, value);
    return 1;
}


int uc_lua__reg_write_batch(lua_State *L) {
    uc_engine *engine;
    int n_registers, error, *registers, i;
    lua_Unsigned *values;
    void **p_values;

    engine = uc_lua__toengine(L, 1);

    /* Second argument will be a table with key-value pairs, the keys being the
     * registers to write to and the values being the values to write to the
     * corresponding registers. */
    n_registers = 0;
    registers = NULL;
    values = NULL;

    lua_pushnil(L);
    while (lua_next(L, 2) != 0) {
        registers = uc_lua__realloc(
            L, registers, (n_registers + 1) * sizeof(*registers));
        values = uc_lua__realloc(
            L, values, (n_registers + 1) * sizeof(*values));

        registers[n_registers] = luaL_checkinteger(L, -2);
        values[n_registers] = (lua_Unsigned)luaL_checkinteger(L, -1);
        lua_pop(L, 1);
    }

    p_values = uc_lua__realloc(L, NULL, n_registers * sizeof(*p_values));
    for (i = 0; i < n_registers; ++i)
        p_values[i] = &values[i];

    error = uc_reg_write_batch(engine, registers, p_values, n_registers);

    free(registers);
    free(values);
    free(p_values);

    if (error != UC_ERR_OK)
        return uc_lua__crash_on_error(L, error);
    return 0;
}


int uc_lua__reg_read_batch(lua_State *L) {
    uc_engine *engine;
    int n_registers, i, error, *registers;
    lua_Integer *values;
    void **p_values;

    engine = uc_lua__toengine(L, 1);

    n_registers = lua_gettop(L) - 1;

    /* Use newuserdata() instead of malloc so we don't have to do any memory
     * management ourselves. */
    registers = (int *)lua_newuserdata(L, n_registers * sizeof(*registers));
    values = (lua_Integer *)lua_newuserdata(L, n_registers * sizeof(*values));
    p_values = (void **)lua_newuserdata(L, n_registers * sizeof(*p_values));

    for (i = 0; i < n_registers; ++i) {
        registers[i] = (int)lua_tointeger(L, i + 2);
        p_values[i] = &values[i];
    }

    memset(values, 0, n_registers * sizeof(*values));
    error = uc_reg_read_batch(engine, registers, p_values, n_registers);

    if (error != UC_ERR_OK)
        return uc_lua__crash_on_error(L, error);

    for (i = 0; i < n_registers; ++i)
        lua_pushinteger(L, values[i]);

    return n_registers;
}
