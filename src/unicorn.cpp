#include <unicorn/unicorn.h>

#include "unicornlua/context.hpp"
#include "unicornlua/engine.hpp"
#include "unicornlua/lua.hpp"
#include "unicornlua/unicornlua.hpp"
#include "unicornlua/utils.hpp"

static int ul_unicorn_version(lua_State* L)
{
    unsigned major, minor;

    uc_version(&major, &minor);
    lua_pushinteger(L, major);
    lua_pushinteger(L, minor);
    return 2;
}

// Create a three-element table that indicates the major, minor, and patch
// versions of this Lua binding.
static int ul_create_unicornlua_version_table(lua_State* L)
{
    lua_createtable(L, 3, 0);

    lua_pushinteger(L, UNICORNLUA_VERSION_MAJOR);
    lua_seti(L, -2, 1);

    lua_pushinteger(L, UNICORNLUA_VERSION_MINOR);
    lua_seti(L, -2, 2);

    lua_pushinteger(L, UNICORNLUA_VERSION_PATCH);
    lua_seti(L, -2, 3);
    return 1;
}

static int ul_arch_supported(lua_State* L)
{
    int is_supported = 0;

    // If the architecture is nil, return false. This allows code to easily
    // determine if an architecture is supported without needing to check the
    // Unicorn version AND assume that the Unicorn library was compiled with all
    // available architectures.
    if (!lua_isnil(L, 1)) {
        auto architecture = static_cast<uc_arch>(luaL_checkinteger(L, 1));
        is_supported = uc_arch_supported(architecture) ? 1 : 0;
    }

    lua_pushboolean(L, is_supported);
    return 1;
}

static int ul_open(lua_State* L)
{
    auto architecture = static_cast<uc_arch>(luaL_checkinteger(L, 1));
    auto mode = static_cast<uc_mode>(luaL_checkinteger(L, 2));

    uc_engine* engine;
    uc_err error = uc_open(architecture, mode, &engine);
    if (error != UC_ERR_OK)
        ul_crash_on_error(L, error);

    // Create a block of memory for the engine userdata and then create the
    // UCLuaEngine in there using placement new. This way, Lua controls the
    // memory and will call the destructor when the engine gets
    // garbage-collected, and we won't have to manage it ourselves.
    void *udata = lua_newuserdata(L, sizeof(UCLuaEngine));
    new (udata) UCLuaEngine(L, engine);

    luaL_setmetatable(L, kEngineMetatableName);

    // Add a mapping of the uc_engine pointer to the engine object we just
    // created, so that hook callbacks can get the engine object knowing only
    // the uc_engine pointer.
    lua_getfield(L, LUA_REGISTRYINDEX, kEnginePointerMapName);
    lua_pushvalue(L, -2); // Duplicate engine object as value
    lua_rawsetp(L, -2, engine);
    lua_pop(L, 1); // Remove pointer map, engine object at TOS again

    return 1;
}

static int ul_strerror(lua_State* L)
{
    auto error = static_cast<uc_err>(luaL_checkinteger(L, 1));
    lua_pushstring(L, uc_strerror(error));
    return 1;
}

static constexpr luaL_Reg kUnicornLibraryFunctions[]
    = { { "arch_supported", ul_arch_supported }, { "open", ul_open },
          { "strerror", ul_strerror }, { "version", ul_unicorn_version },
          { nullptr, nullptr } };

extern "C" UNICORN_EXPORT int luaopen_unicorn(lua_State* L)
{
    // Initialize the engine bits, such as the metatables that engine and
    // context instances use.
    ul_init_engines_lib(L);

    // Create the main library table with all the global functions in it.
    luaL_newlib(L, kUnicornLibraryFunctions);

    // Create a table in the library that contains the major, minor, and patch
    // numbers of the Lua binding. These are positional values, not fields.
    ul_create_unicornlua_version_table(L);
    lua_setfield(L, -2, "LUA_LIBRARY_VERSION");
    return 1;
}
