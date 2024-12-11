#include "unicornlua/register_types.h"
#include "unicornlua/registers.h"
#include "unicornlua/utils.h"
#include <inttypes.h>
#include <lauxlib.h>
#include <lua.h>
#include <stdint.h>
#include <string.h>
#include <unicorn/unicorn.h>

/// @submodule unicorn_c_

/**
 * Get the total number of items in the table, both in the array and mapping parts.
 *
 * `luaL_len()` only returns the number of entries in the array part of a table, so this
 * function iterates through the keys as well.
 */
static size_t count_table_elements(lua_State *L, int table_index)
{
    size_t count;

    // Count the number of keys in the map portion of the table.
    lua_pushnil(L);
    for (count = 0; lua_next(L, table_index) != 0; ++count)
        lua_pop(L, 1);

        // Count the number of keys in the aray portion of the table.
#if LUA_VERSION_NUM >= 502
    count += (size_t)luaL_len(L, table_index);
#else
    for (int i = 1;; i++, count++)
    {
        lua_pushinteger(L, i);
        lua_gettable(L, table_index);
        if (lua_isnil(L, -1))
            break;
        lua_pop(L, 1);
    }
    lua_pop(L, 1);
#endif
    return count;
}

int ul_reg_write(lua_State *L)
{
    uc_engine *engine = (uc_engine *)lua_topointer(L, 1);
    int register_id = (int)luaL_checkinteger(L, 2);
    int_least64_t value = (int_least64_t)luaL_checkinteger(L, 3);

    register_buffer_type buffer;

    memset(buffer, 0, sizeof(buffer));
    *((int_least64_t *)buffer) = value;

    uc_err error = uc_reg_write(engine, register_id, buffer);
    ulinternal_crash_if_failed(
        L, error, "Failed to write value 0x%08" PRIXLEAST64 " to register %d.", value,
        register_id);
    return 0;
}

int ul_reg_write_as(lua_State *L)
{
    uc_engine *engine = (uc_engine *)lua_topointer(L, 1);
    int register_id = (int)luaL_checkinteger(L, 2);
    struct ULRegister reg;

    register__from_lua(&reg, L, 3, 4);

    uc_err error = uc_reg_write(engine, register_id, reg.data);
    ulinternal_crash_if_failed(L, error, "Failed to write to register %d as type %s.",
                               register_id, register__type_id_to_slug(reg.kind));
    return 0;
}

int ul_reg_read(lua_State *L)
{
    uc_engine *engine = (uc_engine *)lua_topointer(L, 1);
    int register_id = (int)luaL_checkinteger(L, 2);

    register_buffer_type value_buffer;
    memset(value_buffer, 0, sizeof(value_buffer));

    // When reading an MSR on an x86 processor, Unicorn requires the buffer to contain the
    // ID of the register to read.
    if (register_id == UC_X86_REG_MSR)
    {
        if (lua_gettop(L) < 3)
        {
            lua_pushstring(
                L, "Reading an x86 model-specific register (MSR) requires an additional"
                   " argument identifying the register to read. You can find a list of"
                   " these in the \"Intel 64 and IA-32 Software Developer's Manual\","
                   " available as PDFs from their website.");
            lua_error(L);
            UL_UNREACHABLE_MARKER;
        }
        *(int *)value_buffer = (int)luaL_checkinteger(L, 3);
    }

    uc_err error = uc_reg_read(engine, register_id, value_buffer);
    ulinternal_crash_if_failed(L, error, "Failed to read register %d", register_id);

    // FIXME (dargueta): This hack doesn't work on big-endian host machines.
    // The astute programmer will notice that reading a register smaller than lua_Integer
    // means that this cast will include memory that Unicorn didn't write to. Fortunately,
    // we cleared `value_buffer` earlier, so that memory will be zeroed out, so the result
    // is predictable. Unfortunately, this strategy only works on a little endian host.
    lua_pushinteger(L, *(lua_Integer *)value_buffer);
    return 1;
}

int ul_reg_read_as(lua_State *L)
{
    uc_engine *engine = (uc_engine *)lua_topointer(L, 1);
    int register_id = (int)luaL_checkinteger(L, 2);

    struct ULRegister reg;
    reg.kind = (enum RegisterDataType)luaL_checkinteger(L, 3);

    if (register_id == UC_X86_REG_MSR)
    {
        lua_pushstring(L, "reg_read_as() doesn't support reading x86 model-specific"
                          " registers, as they have a fixed interpretation.");
        lua_error(L);
        UL_UNREACHABLE_MARKER;
    }

    memset(reg.data, 0, sizeof(reg.data));

    uc_err error = uc_reg_read(engine, register_id, reg.data);
    ulinternal_crash_if_failed(L, error, "Failed to read to register %d as type %s.",
                               register_id, register__type_id_to_slug(reg.kind));

    register__push_to_lua(&reg, L);
    return 1;
}

int ul_reg_write_batch(lua_State *L)
{
    uc_engine *engine = (uc_engine *)lua_topointer(L, 1);

    // Second argument will be a table with key-value pairs, the keys being the registers
    // to write to, and the values being the values to write to these registers.
    size_t n_registers = count_table_elements(L, 2);

    int *register_ids;
    int_least64_t *values;
    void **p_values;

    // Because allocating multiple arrays and freeing on errors is annoying, and also to
    // reduce fragmentation, it's more efficient(?) to allocate all necessary memory at
    // once and do some pointer arithmetic to set up the array pointers where we need
    // them.
    // To use a metaphor: instead of getting chairs one at a time for each person at a
    // table, here we're using a single bench to seat everyone at once.
    char *arena = (char *)malloc(
        n_registers * (sizeof(*register_ids) + sizeof(*values) + sizeof(*p_values)));

    if (arena == NULL)
        ulinternal_crash(L, "Failed to allocate enough memory to bulk write registers.");

    register_ids = (int *)arena;
    values = (int_least64_t *)(arena + (sizeof(*register_ids) * n_registers));
    p_values = (void **)((char *)values + (sizeof(*values) * n_registers));

    // Iterate through the register/value pairs and put them in the corresponding array
    // positions.
    lua_pushnil(L);
    for (size_t i = 0; lua_next(L, 2) != 0; ++i)
    {
        register_ids[i] = (int)luaL_checkinteger(L, -2);
        values[i] = (int_least64_t)luaL_checkinteger(L, -1);
        p_values[i] = &values[i];
        lua_pop(L, 1);
    }

    uc_err error = uc_reg_write_batch(engine, register_ids, p_values, (int)n_registers);
    free(arena);

    ulinternal_crash_if_failed(L, error, "Failed to write %d registers at once.",
                               (int)n_registers);
    return 0;
}

static void prepare_batch_buffers(lua_State *L, size_t n_registers,
                                  register_buffer_type **values, void ***value_pointers)
{
#if LUA_VERSION_NUM >= 504
    *values = lua_newuserdatauv(L, sizeof(register_buffer_type) * n_registers, 0);
    *value_pointers = lua_newuserdatauv(L, n_registers * sizeof(void *), 0);
#else
    *values = lua_newuserdata(L, n_registers * sizeof(register_buffer_type));
    *value_pointers = lua_newuserdata(L, n_registers * sizeof(void *));
#endif

    memset(*values, 0, n_registers * sizeof(register_buffer_type));
    for (size_t i = 0; i < n_registers; ++i)
        (*value_pointers)[i] = &(*values)[i];
}

int ul_reg_read_batch(lua_State *L)
{
    uc_engine *engine = (uc_engine *)lua_topointer(L, 1);
    size_t n_registers = (size_t)lua_gettop(L) - 1;

    if (n_registers == 0)
        return 0;

#if LUA_VERSION_NUM >= 504
    int *register_ids = lua_newuserdatauv(L, n_registers * sizeof(*register_ids), 0);
#else
    int *register_ids = lua_newuserdata(L, n_registers * sizeof(*register_ids));
#endif

    register_buffer_type *values;
    void **value_pointers;

    prepare_batch_buffers(L, n_registers, &values, &value_pointers);

    for (size_t i = 0; i < n_registers; ++i)
        register_ids[i] = (int)lua_tointeger(L, (int)i + 2);

    uc_err error =
        uc_reg_read_batch(engine, register_ids, value_pointers, (int)n_registers);
    ulinternal_crash_if_failed(L, error, "Failed to read %zu registers.", n_registers);

    for (size_t i = 0; i < n_registers; ++i)
        lua_pushinteger(L, *(lua_Integer *)values[i]);

    return (int)n_registers;
}

int ul_reg_read_batch_as(lua_State *L)
{
    uc_engine *engine = (uc_engine *)lua_topointer(L, 1);
    size_t n_registers = count_table_elements(L, 2);

    if (n_registers == 0)
        return 0;

#if LUA_VERSION_NUM >= 504
    int *register_ids =
        (int *)lua_newuserdatauv(L, n_registers * sizeof(*register_ids), 0);
    int *value_types = (int *)lua_newuserdatauv(L, n_registers * sizeof(*value_types), 0);
#else
    int *register_ids = (int *)lua_newuserdata(L, n_registers * sizeof(*register_ids));
    int *value_types = (int *)lua_newuserdata(L, n_registers * sizeof(*value_types));
#endif

    register_buffer_type *values;
    void **value_pointers;

    prepare_batch_buffers(L, n_registers, &values, &value_pointers);

    // Iterate through the second argument -- a table mapping register IDs to the types
    // we want them back as.
    lua_pushnil(L);
    for (size_t i = 0; lua_next(L, 2) != 0; ++i)
    {
        register_ids[i] = (int)luaL_checkinteger(L, -2);
        value_types[i] = (int)luaL_checkinteger(L, -1);
        lua_pop(L, 1);
    }

    uc_err error =
        uc_reg_read_batch(engine, register_ids, value_pointers, (int)n_registers);
    ulinternal_crash_if_failed(
        L, error, "Failed to read %zu registers with alternate types.", n_registers);

    /* Create the table we're going to return the register values in. The result is a
     * key-value mapping where the keys are the register IDs and the values are the
     * typecasted values read from the registers. */
    lua_createtable(L, 0, (int)n_registers);
    for (size_t i = 0; i < n_registers; ++i)
    {
        // Key: register ID
        lua_pushinteger(L, register_ids[i]);

        // Value: Deserialized register
        struct ULRegister register_object = {.kind =
                                                 (enum RegisterDataType)value_types[i]};
        memcpy(&register_object.data, value_pointers[i],
               register__size_for_register_kind(register_object.kind));
        register__push_to_lua(&register_object, L);

        // Set k-v pair.
        lua_rawset(L, -3);
    }

    return 1;
}
