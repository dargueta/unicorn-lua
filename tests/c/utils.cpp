#include <cstring>
#include <csetjmp>

#include "doctest.h"
#include <unicorn/unicorn.h>

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

static jmp_buf gCrashJmpBuffer;
static const char *gExpectedErrorMessage;


static int crash_handler(lua_State *L) {
    const char *error_message = lua_tostring(L, -1);
    CHECK_MESSAGE(
        strcmp(gExpectedErrorMessage, error_message) == 0,
        "Error messages don't match."
    );

    // Error message matches, jump back into the test.
    longjmp(gCrashJmpBuffer, 123);
}


TEST_CASE("ul_crash_on_error() panics with the right error message") {
    lua_State *L = luaL_newstate();
    gExpectedErrorMessage = uc_strerror(UC_ERR_OK);

    int recover_flag = setjmp(gCrashJmpBuffer);
    if (recover_flag == 0) {
        lua_atpanic(L, crash_handler);
        ul_crash_on_error(L, UC_ERR_OK);
        // Execution won't continue past here (inside this block)
    }

    // Returned from the crash handler so we know that the error message matched what
    // we wanted.
    CHECK_EQ(recover_flag, 123);
    lua_close(L);
}
