#include "unicornlua/context.hpp"
#include "doctest.h"
#include "fixtures.hpp"
#include "unicornlua/errors.hpp"

TEST_CASE_FIXTURE(AutoclosingEngineFixture, "Test creating a context")
{
    Context* context = uclua_engine->create_context_in_lua();
    CHECK_NE(context, nullptr);

    CHECK_MESSAGE(
        lua_gettop(L) == 1, "Expecting a context object on the stack.");
    CHECK_MESSAGE(lua_type(L, 1) == LUA_TUSERDATA,
        "Object at top of stack should be userdata.");

    CHECK_MESSAGE((Context*)lua_touserdata(L, 1) == context,
        "TOS isn't the context object we were expecting.");

    // Metatable of the context is at index 2, the expected metatable is at
    // index 3.
    CHECK_MESSAGE(
        lua_getmetatable(L, 1) != 0, "Context object has no metatable.");
    luaL_getmetatable(L, kContextMetatableName);

    CHECK(lua_gettop(L) == 3);

#if LUA_VERSION_NUM < 502
    // lua_compare() was added in 5.2, so we have to use lua_equal() here.
    CHECK_MESSAGE(lua_equal(L, 2, 3) == 1,
        "Context metatable doesn't match the expected one.");
#else
    CHECK_MESSAGE(lua_compare(L, 2, 3, LUA_OPEQ) == 1,
        "Context metatable doesn't match the expected one.");
#endif
    // Clean up the stack
    lua_pop(L, 3);
}

TEST_CASE_FIXTURE(AutoclosingEngineFixture, "Test closing a context")
{
    Context* context = uclua_engine->create_context_in_lua();
    CHECK_NE(context, nullptr);
    CHECK_NE(context->context_handle, nullptr);
    CHECK_NE(context->engine, nullptr);

    // The pointer in the Lua userdata must be identical to the pointer we got
    // back from the function.
    auto userdata = reinterpret_cast<Context*>(lua_touserdata(L, -1));
    REQUIRE_EQ(userdata, context);

    ul_context_free(L);
    CHECK_EQ(context->context_handle, nullptr);

    // Remove the context from the stack.
    lua_pop(L, 1);
}

TEST_CASE_FIXTURE(
    AutoclosingEngineFixture, "Closing a closed context explodes.")
{
    Context* context = uclua_engine->create_context_in_lua();
    CHECK_NE(context->context_handle, nullptr);
    CHECK_NE(context->engine, nullptr);

    ul_context_free(L);
    REQUIRE_EQ(context->context_handle, nullptr);
    REQUIRE_EQ(context->engine, nullptr);

    // Ensure that the context is still on top of the stack, then try freeing
    // it again.
    REQUIRE_EQ(lua_gettop(L), 1);
    REQUIRE_EQ(lua_type(L, 1), LUA_TUSERDATA);
    CHECK_THROWS_AS(ul_context_free(L), LuaBindingError);

    // Remove the context from the stack.
    lua_pop(L, 1);
}

TEST_CASE_FIXTURE(
    AutoclosingEngineFixture, "ul_context_maybe_free is idempotent.")
{
    Context* context = uclua_engine->create_context_in_lua();
    CHECK_NE(context, nullptr);

    // The pointer in the Lua userdata must be identical to the pointer we got
    // back from the function.
    auto userdata = reinterpret_cast<Context*>(lua_touserdata(L, -1));
    REQUIRE_EQ(userdata, context);

    ul_context_maybe_free(L);
    REQUIRE_EQ(context->context_handle, nullptr);
    CHECK_EQ(context->engine, nullptr);

    // Nothing should happen
    ul_context_maybe_free(L);
    CHECK_EQ(context->context_handle, nullptr);
    CHECK_EQ(context->engine, nullptr);

    // Remove the context from the stack.
    lua_pop(L, 1);
}

TEST_CASE_FIXTURE(AutoclosingEngineFixture,
    "Trying to restore from a closed context explodes.")
{
    Context* context = uclua_engine->create_context_in_lua();
    CHECK_NE(context, nullptr);

    ul_context_free(L);
    CHECK_EQ(context->context_handle, nullptr);
    CHECK_EQ(context->engine, nullptr);

    auto userdata = reinterpret_cast<Context*>(lua_touserdata(L, -1));
    CHECK_EQ(userdata, context);
    CHECK_THROWS_AS(
        uclua_engine->restore_from_context(context), LuaBindingError);

    // Remove the context from the stack.
    lua_pop(L, 1);
}
