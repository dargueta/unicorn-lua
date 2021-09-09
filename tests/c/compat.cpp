#include <cstring>
#include <new>

#include "doctest.h"
#include "fixtures.h"
#include "unicornlua/compat.h"
#include "unicornlua/lua.h"
#include "unicornlua/platform.h"

// On LuaJIT + OSX, for some bizarre reason this test invariably either segfaults
// or (more rarely) corrupts the heap. It works just fine in all the other tests
// and never crashes at runtime, at least that I can cause.
#if !(IS_LUAJIT && CMAKE_HOST_APPLE)
TEST_CASE_FIXTURE(LuaFixture, "[5.3 compat] lua_seti() basic") {
    lua_newtable(L);
    lua_pushliteral(L, "This is a string.");

    REQUIRE_EQ(lua_gettop(L), 2);

    lua_seti(L, 1, 5);

    CHECK_EQ(lua_gettop(L), 1);     // Only the table should be on the stack.
    CHECK_EQ(lua_type(L, 1), LUA_TTABLE);    // Verify it's a table

    // Retrieve whatever it is at index 5
    lua_pushinteger(L, 5);
    lua_rawget(L, 1);

    // Should be a string...
    CHECK_EQ(lua_type(L, -1), LUA_TSTRING);

    const char *result = lua_tostring(L, -1);
    CHECK_EQ(strcmp(result, "This is a string."), 0);
}
#endif


TEST_CASE_FIXTURE(LuaFixture, "[5.3 compat] lua_geti() basic") {
    lua_newtable(L);
    lua_pushinteger(L, 1234567890);

    REQUIRE_EQ(lua_gettop(L), 2);

    lua_seti(L, 1, 1);

    CHECK_EQ(lua_gettop(L), 1);     // Only the table should be on the stack.
    CHECK_EQ(lua_type(L, 1), LUA_TTABLE);    // Verify it's a table

    // Retrieve whatever it is at index 1
    lua_geti(L, 1, 1);

    // Should be an integer...
    CHECK_EQ(lua_type(L, -1), LUA_TNUMBER);
    CHECK_EQ(lua_tointeger(L, -1), 1234567890);
}


// TODO (dargueta): Make tests where there's already stuff on the stack.
