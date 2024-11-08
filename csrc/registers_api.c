#include "unicornlua/registers.h"
#include "unicornlua/utils.h"
#include <inttypes.h>
#include <lauxlib.h>
#include <lua.h>
#include <stdint.h>
#include <string.h>
#include <unicorn/unicorn.h>

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
    struct Register reg;

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
                L, "Reading an x86 model-specific register (MSR) requires"
                   " an additional argument identifying the register to read. You"
                   " can find a list of these in the \"Intel 64 and IA-32 Software"
                   " Developer's Manual\", available as PDFs from their website.");
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

    struct Register reg;
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

    /* Second argument will be a table with key-value pairs, the keys being the registers
     * to write to, and the values being the values to write to these registers. */
    size_t n_registers = count_table_elements(L, 2);

    int *register_ids = malloc(sizeof(*register_ids) * n_registers);
    int_least64_t *values = malloc(sizeof(*values) * n_registers);
    void **p_values = malloc(sizeof(*p_values) * n_registers);

    /* Iterate through the register/value pairs and put them in the corresponding array
     * positions. */
    lua_pushnil(L);
    for (size_t i = 0; lua_next(L, 2) != 0; ++i)
    {
        register_ids[i] = (int)luaL_checkinteger(L, -2);
        values[i] = (int_least64_t)luaL_checkinteger(L, -1);
        p_values[i] = &values[i];
        lua_pop(L, 1);
    }

    uc_err error = uc_reg_write_batch(engine, register_ids, p_values, (int)n_registers);
    free(register_ids);
    free(values);
    free(p_values);

    ulinternal_crash_if_failed(L, error, "Failed to write %d registers at once.",
                               (int)n_registers);
    return 0;
}

static void prepare_batch_buffers(size_t n_registers, register_buffer_type **values,
                                  void ***value_pointers)
{
    *values = calloc(sizeof(register_buffer_type), n_registers);
    *value_pointers = malloc(n_registers * sizeof(void *));

    for (size_t i = 0; i < n_registers; ++i)
        (*value_pointers)[i] = &(*values)[i];
}

#if 0
int ul_reg_read_batch(lua_State *L)
{
    uc_engine *engine = ul_toengine(L, 1);
    auto n_registers = static_cast<size_t>(lua_gettop(L)) - 1;

    std::unique_ptr<int[]> register_ids(new int[n_registers]);
    std::unique_ptr<register_buffer_type[]> values;
    std::unique_ptr<void *[]> value_pointers;

    prepare_batch_buffers(n_registers, values, value_pointers);
    for (size_t i = 0; i < n_registers; ++i)
        register_ids[i] = static_cast<int>(lua_tointeger(L, static_cast<int>(i) + 2));

    uc_err error = uc_reg_read_batch(engine, register_ids.get(), value_pointers.get(),
                                     static_cast<int>(n_registers));
    if (error != UC_ERR_OK)
        ul_crash_on_error(L, error);

    for (size_t i = 0; i < n_registers; ++i)
    {
        lua_pushinteger(L, *reinterpret_cast<lua_Integer *>(values[i]));
    }
    return static_cast<int>(n_registers);
}

int ul_reg_read_batch_as(lua_State *L)
{
    uc_engine *engine = ul_toengine(L, 1);
    size_t n_registers = count_table_elements(L, 2);

    std::unique_ptr<int[]> register_ids(new int[n_registers]);
    std::unique_ptr<int[]> value_types(new int[n_registers]);
    std::unique_ptr<register_buffer_type[]> values;
    std::unique_ptr<void *[]> value_pointers;

    prepare_batch_buffers(n_registers, values, value_pointers);

    // Iterate through the second argument -- a table mapping register IDs to
    // the types we want them back as.
    lua_pushnil(L);
    for (size_t i = 0; lua_next(L, 2) != 0; ++i)
    {
        register_ids[i] = (int)luaL_checkinteger(L, -2);
        value_types[i] = (int)luaL_checkinteger(L, -1);
        lua_pop(L, 1);
    }

    uc_err error = uc_reg_read_batch(engine, register_ids.get(), value_pointers.get(),
                                     static_cast<int>(n_registers));
    if (error != UC_ERR_OK)
        ul_crash_on_error(L, error);

    // Create the table we're going to return the register values in. The result
    // is a key-value mapping where the keys are the register IDs and the values
    // are the typecasted values read from the registers.
    lua_createtable(L, 0, static_cast<int>(n_registers));
    for (size_t i = 0; i < n_registers; ++i)
    {
        // Key: register ID
        lua_pushinteger(L, register_ids[i]);

        // Value: Deserialized register
        auto register_object =
            Register(value_pointers[i], static_cast<RegisterDataType>(value_types[i]));
        register_object.push_to_lua(L);
        lua_settable(L, -3);
    }

    return 1;
}
#else
int ul_reg_read_batch(lua_State *L)
{
    ulinternal_crash_not_implemented(L);
}

int ul_reg_read_batch_as(lua_State *L)
{
    ulinternal_crash_not_implemented(L);
}
#endif
