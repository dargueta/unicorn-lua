#include <cstring>
#include <csetjmp>
#include <stdexcept>

#include <unicorn/unicorn.h>

#include "doctest.h"
#include "fixtures.h"
#include "unicornlua/lua.h"
#include "unicornlua/platform.h"
#include "unicornlua/utils.h"


// FIXME (dargueta): Something's wrong with this test and it's not working right.
#if 0
TEST_CASE_FIXTURE(LuaFixture, "[ul_create_weak_table] basic test -- weak values") {
    // Create some objects in the C registry
    lua_newtable(L);
    int first = luaL_ref(L, LUA_REGISTRYINDEX);
    lua_pushinteger(L, 1234567890);
    int second = luaL_ref(L, LUA_REGISTRYINDEX);

    ul_create_weak_table(L, "v");

    // Verify the metatable is correct
    CHECK_MESSAGE(lua_getmetatable(L, -1) != 0, "Metatable is missing.");
    lua_getfield(L, -1, "__mode");
    REQUIRE_FALSE_MESSAGE(lua_isnil(L, -1), "__mode not set in metatable.");
    REQUIRE_MESSAGE(strcmp(lua_tostring(L, -1), "v") == 0, "__mode isn't \"v\"");

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
    CHECK_MESSAGE(luaL_len(L, -1) < 2, "Values weren't removed from the table.");
}
#endif


jmp_buf gCrashJmpBuffer;
const char *gExpectedErrorMessage;

int crash_handler(lua_State *L) {
    const char *error_message = lua_tostring(L, -1);
    CHECK_MESSAGE(
        strcmp(gExpectedErrorMessage, error_message) == 0,
        "Error messages don't match."
    );

    // Error message matches, jump back into the test.
    longjmp(gCrashJmpBuffer, 123);
}


TEST_CASE_FIXTURE(
    LuaFixture, "ul_crash_on_error() panics with the right error message"
) {
    gExpectedErrorMessage = uc_strerror(UC_ERR_OK);

#if !IS_LUAJIT
    int recover_flag = setjmp(gCrashJmpBuffer);
    if (recover_flag == 0) {
        lua_atpanic(L, crash_handler);
        ul_crash_on_error(L, UC_ERR_OK);
        // Execution won't continue past here (inside this block)
    }

    // Returned from the crash handler so we know that the error message matched what
    // we wanted.
    CHECK_EQ(recover_flag, 123);
#else
    try {
        ul_crash_on_error(L, UC_ERR_OK);
    }
    catch (...) {
        // Some sort of unhandled exception happened. LuaJIT doesn't provide a way for
        // us to see inside that exception, but we *can* check the error message.
        CHECK_MESSAGE(
            strcmp(lua_tostring(L, -1), uc_strerror(UC_ERR_OK)) == 0,
            "Error message doesn't match what's expected."
        );
        return;
    }
    // If we get out here then an exception wasn't thrown.
    FAIL("Exception wasn't thrown.");
#endif
}

#if 0
typedef char ItemType[100];


TEST_CASE_FIXTURE(LuaFixture, "WeakLuaAllocator: Allocation works") {
    WeakLuaAllocator<ItemType> allocator(L);
    CHECK_EQ(allocator.size(), 0);

    int original_stack_top = lua_gettop(L);

    ItemType *new_item = allocator.allocate();
    CHECK_NE(new_item, nullptr);
    // Should have one element in the table.
    CHECK_EQ(allocator.size(), 1);

    // Hopefully if this is an invalid pointer doing a memset will crash.
    memset(new_item, 0, sizeof(ItemType));

    // Ensure that there's one new item on top of the stack. This is the userdata
    // that we just allocated.
    CHECK_EQ(original_stack_top + 1, lua_gettop(L));

    // Ensure the userdata pointer we get back is identical to the pointer we
    // got back from allocate().
    auto userdata = reinterpret_cast<ItemType *>(lua_touserdata(L, -1));
    CHECK_EQ(userdata, new_item);

    CHECK_MESSAGE(
        lua_gettop(L) == original_stack_top + 1,
        "Stack wasn't restored to its original state after size()."
    );
}


TEST_CASE_FIXTURE(LuaFixture, "WeakLuaAllocator: Freeing works") {
    WeakLuaAllocator<ItemType> allocator(L);
    CHECK_EQ(allocator.size(), 0);

    ItemType *new_item = allocator.allocate();
    CHECK_NE(new_item, nullptr);

    // Should have one element in the table.
    CHECK_EQ(allocator.size(), 1);

    allocator.free(new_item);
    CHECK_EQ(allocator.size(), 0);
}


TEST_CASE_FIXTURE(LuaFixture, "WeakLuaAllocator: Double free crashes") {
    WeakLuaAllocator<ItemType> allocator(L);
    CHECK_EQ(allocator.size(), 0);

    ItemType *new_item = allocator.allocate();
    CHECK_NE(new_item, nullptr);
    CHECK_EQ(allocator.size(), 1);

    allocator.free(new_item);
    CHECK_EQ(allocator.size(), 0);

    CHECK_THROWS_AS(allocator.free(new_item), std::invalid_argument);
    CHECK_EQ(allocator.size(), 0);
}


TEST_CASE_FIXTURE(LuaFixture, "WeakLuaAllocator: Weak references work") {
    WeakLuaAllocator<ItemType> allocator(L);
    CHECK_EQ(allocator.size(), 0);

    // Allocate a new item. Since all references are weak references, once this
    // is popped from the stack, it should get cleaned up on the next collection
    // cycle.
    ItemType *item = allocator.allocate();
    CHECK_NE(item, nullptr);
    CHECK_EQ(allocator.size(), 1);

    // Remove the only strong reference to the thing we just allocated.
    lua_pop(L, 1);

    // Force a garbage collection cycle, which should remove our item.
    lua_gc(L, LUA_GCCOLLECT, 0);
    CHECK_MESSAGE(
        allocator.size() == 0,
        "Weak reference didn't work, allocator still has 1 element."
    );
}
#endif
