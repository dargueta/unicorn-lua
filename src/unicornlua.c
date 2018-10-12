#include <stdlib.h>

#include <lauxlib.h>
#include <lua.h>
#include <unicorn/unicorn.h>

#include "unicornlua/common.h"
#include "unicornlua/unicornlua.h"
#include "unicornlua/constants/arm.h"
#include "unicornlua/constants/arm64.h"
#include "unicornlua/constants/globals.h"
#include "unicornlua/constants/m68k.h"
#include "unicornlua/constants/mips.h"
#include "unicornlua/constants/sparc.h"
#include "unicornlua/constants/x86.h"

static const char *kEngineMetatableName = "unicornlua__engine_meta";
static const char *kContextMetatableName = "unicornlua__context_meta";


static int _crash_on_error(lua_State *L, int error) {
    const char *message;

    message = uc_strerror(error);
    lua_pushstring(L, message);
    return lua_error(L);
}


static void *_safe_realloc(lua_State *L, void *ptr, size_t new_size) {
    void *tmp = realloc(ptr, new_size);
    if (tmp == NULL) {
        luaL_error(L, "Out of memory.");
        return NULL;
    }
    return tmp;
}


int uc_lua__version(lua_State *L) {
    unsigned major, minor;

    uc_version(&major, &minor);
    lua_createtable(L, 0, 2);

    lua_pushinteger(L, major);
    lua_setfield(L, -2, "major");

    lua_pushinteger(L, minor);
    lua_setfield(L, -2, "minor");
    return 1;
}


int uc_lua__arch_supported(lua_State *L) {
    int architecture = luaL_checkinteger(L, -1);
    lua_pushboolean(L, uc_arch_supported(architecture));
    return 1;
}


int uc_lua__open(lua_State *L) {
    int architecture, mode, error_code;
    uc_engine **engine;

    architecture = luaL_checkinteger(L, 1);
    mode = luaL_checkinteger(L, 2);

    engine = lua_newuserdata(L, sizeof(*engine));

    error_code = uc_open(architecture, mode, engine);
    if (error_code != UC_ERR_OK)
        return _crash_on_error(L, error_code);

    luaL_setmetatable(L, kEngineMetatableName);
    return 1;
}


int uc_lua__strerror(lua_State *L) {
    lua_pushstring(L, uc_strerror(luaL_checkinteger(L, 1)));
    return 1;
}


int uc_lua__close(lua_State *L) {
    uc_engine *engine;
    int error;

    engine = *(uc_engine **)luaL_checkudata(L, 1, kEngineMetatableName);

#if 0
    /* If the engine is already closed, don't try closing it again. Since the
     * engine is automatically closed when it gets garbage collected, if the
     * user manually closes it first this will result in an attempt to close an
     * already-closed engine. Hence, this flag.
     */
    lua_getfield(L, 1, "__is_closed");
    if (lua_toboolean(L, -1))
        return 0;

    lua_pop(L, 1);
#endif
    error = uc_close(engine);
    if (error != UC_ERR_OK)
        return _crash_on_error(L, error);
#if 0
    lua_pushboolean(L, 1);
    lua_setfield(L, -2, "__is_closed");
#endif
    return 0;
}


int uc_lua__query(lua_State *L) {
    uc_engine *engine;
    int query_type, error;
    size_t result;

    engine = *(uc_engine **)luaL_checkudata(L, 1, kEngineMetatableName);
    query_type = luaL_checkinteger(L, 1);

    error = uc_query(engine, query_type, &result);
    if (error != UC_ERR_OK)
        return _crash_on_error(L, error);

    lua_pushinteger(L, result);
    return 1;
}


int uc_lua__errno(lua_State *L) {
    uc_engine *engine;

    engine = *(uc_engine **)luaL_checkudata(L, 1, kEngineMetatableName);
    lua_pushinteger(L, uc_errno(engine));
    return 1;
}


int uc_lua__reg_write(lua_State *L) {
    uc_engine *engine;
    int register_id, error;
    lua_Integer value;

    engine = *(uc_engine **)luaL_checkudata(L, 1, kEngineMetatableName);
    register_id = luaL_checkinteger(L, 2);
    value = luaL_checkinteger(L, 3);

    error = uc_reg_write(engine, register_id, &value);
    if (error != UC_ERR_OK)
        return _crash_on_error(L, error);

    return 0;
}


int uc_lua__reg_read(lua_State *L) {
    uc_engine *engine;
    int register_id, error;
    lua_Integer value;

    engine = *(uc_engine **)luaL_checkudata(L, 1, kEngineMetatableName);
    register_id = luaL_checkinteger(L, 2);

    error = uc_reg_read(engine, register_id, &value);
    if (error != UC_ERR_OK)
        return _crash_on_error(L, error);

    lua_pushinteger(L, value);
    return 1;
}


int uc_lua__reg_write_batch(lua_State *L) {
    uc_engine *engine;
    int n_registers, error, *registers, i;
    lua_Integer *values;
    void **p_values;

    engine = *(uc_engine **)luaL_checkudata(L, 1, kEngineMetatableName);

    /* Second argument will be a table with key-value pairs, the keys being the
     * registers to write to and the values being the values to write to the
     * corresponding registers. */
    n_registers = 0;
    registers = NULL;
    values = NULL;

    lua_pushnil(L);
    while (lua_next(L, 2) != 0) {
        registers = _safe_realloc(
            L, registers, (n_registers + 1) * sizeof(*registers));
        values = _safe_realloc(
            L, values, (n_registers + 1) * sizeof(*values));

        registers[n_registers] = luaL_checkinteger(L, -2);
        values[n_registers] = luaL_checkinteger(L, -1);
        lua_pop(L, 1);
    }

    p_values = _safe_realloc(L, NULL, n_registers * sizeof(*p_values));
    for (i = 0; i < n_registers; ++i)
        p_values[i] = &values[i];

    error = uc_reg_write_batch(engine, registers, p_values, n_registers);

    free(registers);
    free(values);
    free(p_values);

    if (error != UC_ERR_OK)
        return _crash_on_error(L, error);
    return 0;
}

int uc_lua__reg_read_batch(lua_State *L) {
    uc_engine *engine;
    int n_registers, i, error, *registers;
    lua_Integer *values;
    void **p_values;

    engine = *(uc_engine **)luaL_checkudata(L, 1, kEngineMetatableName);

    /* Second argument is a table a list of the register IDs to read. Get the
     * length. */
    lua_len(L, 2);
    n_registers = lua_tointeger(L, -1);
    lua_pop(L, 1);

    /* Use newuserdata() instead of malloc so we don't have to do any memory
     * management ourselves. */
    registers = (int *)lua_newuserdata(L, n_registers * sizeof(*registers));
    values = (lua_Integer *)lua_newuserdata(L, n_registers * sizeof(*values));
    p_values = (void **)lua_newuserdata(L, n_registers * sizeof(*p_values));

    for (i = 0; i < n_registers; ++i) {
        lua_geti(L, 2, i + 1);
        registers[i] = lua_tointeger(L, -1);
        lua_pop(L, 1);

        p_values[i] = &values[i];
    }

    error = uc_reg_read_batch(engine, registers, p_values, n_registers);

    if (error != UC_ERR_OK)
        return _crash_on_error(L, error);

    lua_createtable(L, 0, n_registers);
    for (i = 0; i < n_registers; ++i) {
        lua_pushinteger(L, registers[i]);
        lua_pushinteger(L, values[i]);
        lua_settable(L, -2);
    }

    return 1;
}


int uc_lua__mem_write(lua_State *L) {
    uc_engine *engine;
    lua_Unsigned address;
    const void *data;
    size_t length;
    int error;

    engine = *(uc_engine **)luaL_checkudata(L, 1, kEngineMetatableName);
    address = (lua_Unsigned)luaL_checkinteger(L, 2);
    data = (const void *)luaL_checklstring(L, 3, &length);

    error = uc_mem_write(engine, address, data, length);
    if (error != UC_ERR_OK)
        return _crash_on_error(L, error);

    return 0;
}

int uc_lua__mem_read(lua_State *L) {
    uc_engine *engine;
    lua_Unsigned address;
    void *data;
    lua_Integer length;
    int error;

    engine = *(uc_engine **)luaL_checkudata(L, 1, kEngineMetatableName);
    address = (lua_Unsigned)luaL_checkinteger(L, 2);
    length = luaL_checkinteger(L, 3);

    if (length < 0)
        return luaL_error(L, "Read length must be > 0, not %d", length);

    data = _safe_realloc(L, NULL, length);

    error = uc_mem_read(engine, address, data, (size_t)length);
    if (error != UC_ERR_OK) {
        free(data);
        return _crash_on_error(L, error);
    }

    lua_pushlstring(L, data, length);
    return 1;
}

int uc_lua__emu_start(lua_State *L) {
    uc_engine *engine;
    lua_Unsigned start, end, timeout, n_instructions;
    int error;

    engine = *(uc_engine **)luaL_checkudata(L, 1, kEngineMetatableName);
    start = (lua_Unsigned)luaL_checkinteger(L, 2);
    end = (lua_Unsigned)luaL_checkinteger(L, 3);
    timeout = (lua_Unsigned)luaL_optinteger(L, 4, 0);
    n_instructions = (lua_Unsigned)luaL_optinteger(L, 5, 0);

    error = uc_emu_start(engine, start, end, timeout, n_instructions);
    if (error != UC_ERR_OK)
        return _crash_on_error(L, error);
    return 0;
}


int uc_lua__emu_stop(lua_State *L) {
    uc_engine *engine;
    int error;

    engine = *(uc_engine **)luaL_checkudata(L, 1, kEngineMetatableName);

    error = uc_emu_stop(engine);
    if (error != UC_ERR_OK)
        return _crash_on_error(L, error);
    return 0;
}


int uc_lua__hook_add(lua_State *L) {
    return luaL_error(L, "Not implemented yet.");
}


int uc_lua__hook_del(lua_State *L) {
    return luaL_error(L, "Not implemented yet.");
}


int uc_lua__mem_map(lua_State *L) {
    uc_engine *engine;
    lua_Unsigned address, size, perms;
    int error;

    engine = *(uc_engine **)luaL_checkudata(L, 1, kEngineMetatableName);
    address = (lua_Unsigned)luaL_checkinteger(L, 2);
    size = (lua_Unsigned)luaL_checkinteger(L, 3);
    perms = (lua_Unsigned)luaL_optinteger(L, 4, UC_PROT_ALL);

    error = uc_mem_map(engine, address, size, perms);
    if (error != UC_ERR_OK)
        return _crash_on_error(L, error);
    return 0;
}


int uc_lua__mem_unmap(lua_State *L) {
    uc_engine *engine;
    lua_Unsigned address, size;
    int error;

    engine = *(uc_engine **)luaL_checkudata(L, 1, kEngineMetatableName);
    address = (lua_Unsigned)luaL_checkinteger(L, 2);
    size = (lua_Unsigned)luaL_checkinteger(L, 3);

    error = uc_mem_unmap(engine, address, size);
    if (error != UC_ERR_OK)
        return _crash_on_error(L, error);
    return 0;
}

int uc_lua__mem_protect(lua_State *L) {
    uc_engine *engine;
    lua_Unsigned address, size, perms;
    int error;

    engine = *(uc_engine **)luaL_checkudata(L, 1, kEngineMetatableName);
    address = (lua_Unsigned)luaL_checkinteger(L, 2);
    size = (lua_Unsigned)luaL_checkinteger(L, 3);
    perms = (lua_Unsigned)luaL_checkinteger(L, 4);

    error = uc_mem_protect(engine, address, size, perms);
    if (error != UC_ERR_OK)
        return _crash_on_error(L, error);
    return 0;
}

int uc_lua__mem_regions(lua_State *L) {
    uc_engine *engine;
    uc_mem_region *regions;
    uint32_t n_regions, i;
    int error;

    engine = *(uc_engine **)luaL_checkudata(L, 1, kEngineMetatableName);
    regions = NULL;
    n_regions = 0;

    error = uc_mem_regions(engine, &regions, &n_regions);
    if (error != UC_ERR_OK)
        return _crash_on_error(L, error);

    lua_createtable(L, n_regions, 0);

    for (i = 0; i < n_regions; ++i) {
        lua_createtable(L, 0, 3);

        lua_pushinteger(L, regions[i].begin);
        lua_setfield(L, -1, "begin");

        lua_pushinteger(L, regions[i].end);
        lua_setfield(L, -1, "end");

        lua_pushinteger(L, regions[i].perms);
        lua_setfield(L, -1, "perms");

        lua_seti(L, -2, i + 1);
    }

    uc_free(regions);
    return 1;
}


int uc_lua__free(lua_State *L) {
    int error = uc_free(lua_touserdata(L, 1));

    if (error != UC_ERR_OK)
        return _crash_on_error(L, error);
    return 0;
}


int uc_lua__context_alloc(lua_State *L) {
    uc_engine *engine;
    uc_context **context;
    int error;

    engine = *(uc_engine **)luaL_checkudata(L, 1, kEngineMetatableName);

    context = (uc_context **)lua_newuserdata(L, sizeof(*context));
    luaL_setmetatable(L, kContextMetatableName);

    error = uc_context_alloc(engine, context);
    if (error != UC_ERR_OK)
        return _crash_on_error(L, error);

    lua_pushlightuserdata(L, engine);
    lua_setfield(L, -2, "__engine");
    return 1;
}


int uc_lua__context_save(lua_State *L) {
    uc_engine *engine;
    uc_context *context;
    int error;

    uc_lua__context_alloc(L);

    engine = *(uc_engine **)luaL_checkudata(L, 1, kEngineMetatableName);
    context = (uc_context *)luaL_checkudata(L, 2, kContextMetatableName);

    error = uc_context_save(engine, context);
    if (error != UC_ERR_OK)
        return _crash_on_error(L, error);

    return 1;
}


int uc_lua__context_update(lua_State *L) {
    uc_engine *engine;
    uc_context *context;
    int error;

    context = (uc_context *)luaL_checkudata(L, 1, kContextMetatableName);
    lua_getfield(L, -1, "__engine");
    engine = lua_touserdata(L, -1);

    error = uc_context_save(engine, context);
    if (error != UC_ERR_OK)
        return _crash_on_error(L, error);
    return 0;
}


int uc_lua__context_restore(lua_State *L) {
    uc_engine *engine;
    uc_context *context;
    int error;

    engine = *(uc_engine **)luaL_checkudata(L, 1, kEngineMetatableName);
    context = (uc_context *)luaL_checkudata(L, 2, kContextMetatableName);

    error = uc_context_restore(engine, context);
    if (error != UC_ERR_OK)
        return _crash_on_error(L, error);
    return 0;
}


static const luaL_Reg kUnicornLibraryFunctions[] = {
    {"arch_supported", uc_lua__arch_supported},
    {"open", uc_lua__open},
    {"strerror", uc_lua__strerror},
    {"version", uc_lua__version},
    {NULL, NULL}
};


static const luaL_Reg kEngineMetamethods[] = {
    {"__gc", uc_lua__close},
    {NULL, NULL}
};

static const luaL_Reg kEngineInstanceMethods[] = {
    {"close", uc_lua__close},
    {"context_restore", uc_lua__context_restore},
    {"context_save", uc_lua__context_save},
    {"emu_start", uc_lua__emu_start},
    {"emu_stop", uc_lua__emu_stop},
    {"errno", uc_lua__errno},
    {"hook_add", uc_lua__hook_add},
    {"hook_del", uc_lua__hook_del},
    {"mem_map", uc_lua__mem_map},
    {"mem_protect", uc_lua__mem_protect},
    {"mem_read", uc_lua__mem_read},
    {"mem_regions", uc_lua__mem_regions},
    {"mem_unmap", uc_lua__mem_unmap},
    {"mem_write", uc_lua__mem_write},
    {"query", uc_lua__query},
    {"reg_read", uc_lua__reg_read},
    {"reg_read_batch", uc_lua__reg_read_batch},
    {"reg_write", uc_lua__reg_write},
    {"reg_write_batch", uc_lua__reg_write_batch},
    {NULL, NULL}
};


static const luaL_Reg kContextMetamethods[] = {
    {"__gc", uc_lua__free},
    {NULL, NULL}
};


static const luaL_Reg kContextInstanceMethods[] = {
    {"update", uc_lua__context_update},
    {NULL, NULL}
};


static int _load_int_constants(lua_State *L, const struct NamedIntConst *constants) {
    int i;

    for (i = 0; constants[i].name != NULL; ++i) {
        /* For some reason I can't get lua_setfield() to work. */
        lua_pushstring(L, constants[i].name);
        lua_pushinteger(L, constants[i].value);
        lua_settable(L, -3);
    }

    return i;
}


int luaopen_unicorn(lua_State *L) {
    luaL_newmetatable(L, kEngineMetatableName);
    luaL_setfuncs(L, kEngineMetamethods, 0);

    lua_createtable(L, 0, 0);
    luaL_setfuncs(L, kEngineInstanceMethods, 0);
    lua_setfield(L, -2, "__index");

    luaL_newmetatable(L, kContextMetatableName);
    luaL_setfuncs(L, kContextMetamethods, 0);

    lua_createtable(L, 0, 0);
    luaL_setfuncs(L, kContextInstanceMethods, 0);
    lua_setfield(L, -2, "__index");

    luaL_newlib(L, kUnicornLibraryFunctions);
    _load_int_constants(L, kGlobalsConstants);
    return 1;
}
// make clean && make && LUA_CPATH="./bin/?.dylib;$LUA_CPATH" lua tests/lua/tutorial.lua

int luaopen_unicorn_arm64(lua_State *L) {
    lua_newtable(L);
    _load_int_constants(L, kARM64Constants);
    return 1;
}


int luaopen_unicorn_arm(lua_State *L) {
    lua_newtable(L);
    _load_int_constants(L, kARMConstants);
    return 1;
}


int luaopen_unicorn_m68k(lua_State *L) {
    lua_newtable(L);
    _load_int_constants(L, kM68KConstants);
    return 1;
}


int luaopen_unicorn_mips(lua_State *L) {
    lua_newtable(L);
    _load_int_constants(L, kMIPSConstants);
    return 1;
}


int luaopen_unicorn_sparc(lua_State *L) {
    lua_newtable(L);
    _load_int_constants(L, kSPARCConstants);
    return 1;
}


int luaopen_unicorn_x86(lua_State *L) {
    lua_newtable(L);
    _load_int_constants(L, kX86Constants);
    return 1;
}
