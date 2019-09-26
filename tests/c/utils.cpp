#include <cstring>

#include "doctest.h"

#include "unicornlua/lua.h"
#include "unicornlua/utils.h"


// TODO (dargueta): Something's wrong with this test and it's not working right.
#if 0

TEST_CASE("[ul_create_weak_table] basic test -- weak values") {
    lua_State *L = luaL_newstate();

    // Create some objects in the C registry
    lua_newtable(L);
    int first = luaL_ref(L, LUA_REGISTRYINDEX);
    lua_pushinteger(L, 1234567890);
    int second = luaL_ref(L, LUA_REGISTRYINDEX);

    ul_create_weak_table(L, "v");

    // Verify the metatable is correct
    CHECK_MESSAGE(lua_getmetatable(L, -1) != 0, "Metatable is missing.");
    lua_getfield(L, -1, "__mode");
    CHECK_FALSE_MESSAGE(lua_isnil(L, -1), "__mode not set in metatable.");
    CHECK_MESSAGE(strcmp(lua_tostring(L, -1), "v") == 0, "__mode isn't \"v\"");

    // Remove __mode value and the metatable from the stack. Our test table is back at the
    // top of the stack.
    lua_pop(L, 2);

    // Assign our values into the weak table.
    lua_geti(L, LUA_REGISTRYINDEX, first);
    lua_seti(L, -2, 1);
    lua_geti(L, LUA_REGISTRYINDEX, second);
    lua_seti(L, -2, 2);

    CHECK_MESSAGE(luaL_len(L, -1) == 2, "Wrong number of items in weak table.");

    // Table appears to be correct. Remove the objects from the table, force a garbage
    // collection cycle, and then verify the table is empty.
    luaL_unref(L, LUA_REGISTRYINDEX, first);
    luaL_unref(L, LUA_REGISTRYINDEX, second);
    lua_gc(L, LUA_GCRESTART, 0);
    lua_gc(L, LUA_GCCOLLECT, 0);

    // Only the table should've gotten removed, as integers aren't subject to garbage
    // collection.
    CHECK_MESSAGE(luaL_len(L, -1) == 1, "Values weren't removed from the table.");

    lua_close(L);
}

#endif
