#include <utility>

#include <unicorn/unicorn.h>

#include "unicornlua/lua.hpp"
#include "unicornlua/utils.hpp"

void ul_crash_on_error(lua_State* L, uc_err error)
{
    const char* message = uc_strerror(error);
    lua_checkstack(L, 1);
    lua_pushstring(L, message);
    lua_error(L);
#if defined(__cpp_lib_unreachable)
    std::unreachable();
#elif defined(__GNUC__) // GCC, Clang, ICC
    __builtin_unreachable();
#elif defined(_MSC_VER) // MSVC
    __assume(false);
#endif
}

void ul_create_weak_table(lua_State* L, const char* mode)
{
    lua_newtable(L);
    lua_createtable(L, 0, 1);
    lua_pushstring(L, mode);
    lua_setfield(L, -2, "__mode");
    lua_setmetatable(L, -2);
}

void load_int_constants(lua_State* L, const struct NamedIntConst* constants)
{
    for (int i = 0; constants[i].name != nullptr; ++i) {
        lua_pushinteger(L, constants[i].value);
        lua_setfield(L, -2, constants[i].name);
    }
}

size_t count_table_elements(lua_State* L, int table_index)
{
    size_t count = 0;

    lua_pushnil(L);
    for (count = 0; lua_next(L, table_index) != 0; ++count)
        lua_pop(L, 1);
    return count;
}
