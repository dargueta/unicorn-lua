#include <lauxlib.h>
#include <lua.h>
#include <unicorn/unicorn.h>

#include "unicornlua/compat.h"
#include "unicornlua/numbers.h"
#include "unicornlua/utils.h"


int uc_lua__reg_write(lua_State *L) {
    uc_engine *engine;
    int register_id, error;
    lua_Unsigned value;

    engine = uc_lua__toengine(L, 1);
    register_id = luaL_checkinteger(L, 2);
    value = uc_lua__cast_unsigned(L, 3);

    error = uc_reg_write(engine, register_id, &value);
    if (error != UC_ERR_OK)
        return uc_lua__crash_on_error(L, error);

    return 0;
}


int uc_lua__reg_read(lua_State *L) {
    uc_engine *engine;
    int register_id, error;
    lua_Unsigned value;

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
        values[n_registers] = uc_lua__cast_unsigned(L, -1);
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

    /* Second argument is a table a list of the register IDs to read. Get the
     * length. */
    #if LUA_VERSION_NUM >= 502
        /* Lua 5.2+ */
        lua_len(L, 2);
    #else
        /* Lua 5.1 */
        lua_pushinteger(L, (lua_Integer)lua_objlen(L, 2));
    #endif

    n_registers = lua_tointeger(L, -1);
    lua_pop(L, 1);

    /* Use newuserdata() instead of malloc so we don't have to do any memory
     * management ourselves. */
    registers = (int *)lua_newuserdata(L, n_registers * sizeof(*registers));
    values = (lua_Integer *)lua_newuserdata(L, n_registers * sizeof(*values));
    p_values = (void **)lua_newuserdata(L, n_registers * sizeof(*p_values));

    for (i = 0; i < n_registers; ++i) {
        #if LUA_VERSION_NUM >= 503
            lua_geti(L, 2, i + 1);
        #else
            lua_pushinteger(L, i + 1);
            lua_gettable(L, 2);
        #endif
        registers[i] = lua_tointeger(L, -1);
        lua_pop(L, 1);

        p_values[i] = &values[i];
    }

    error = uc_reg_read_batch(engine, registers, p_values, n_registers);

    if (error != UC_ERR_OK)
        return uc_lua__crash_on_error(L, error);

    lua_createtable(L, 0, n_registers);
    for (i = 0; i < n_registers; ++i) {
        lua_pushinteger(L, registers[i]);
        lua_pushinteger(L, values[i]);
        lua_settable(L, -2);
    }

    return 1;
}
