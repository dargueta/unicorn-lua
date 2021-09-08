#include "doctest.h"
#include "fixtures.h"
#include "unicornlua/context.h"
#include "unicornlua/errors.h"


TEST_CASE_FIXTURE(AutoclosingEngineFixture, "Test creating a context") {
    Context *context = uclua_engine->create_context_in_lua();
    CHECK_NE(context, nullptr);

    CHECK_MESSAGE(
        lua_gettop(L) == 1, "Expecting a context object on the stack."
    );
    CHECK_MESSAGE(
        lua_type(L, 1) == LUA_TUSERDATA, "Object at top of stack should be userdata."
    );

    CHECK_MESSAGE(
        *(Context **)lua_touserdata(L, 1) == context,
        "TOS isn't the context object we were expecting."
    );

    // Metatable of the context is at index 2, the expected metatable is at index 3.
    CHECK_MESSAGE(
        lua_getmetatable(L, 1) != 0, "Context object has no metatable."
    );
    luaL_getmetatable(L, kContextMetatableName);

    CHECK(lua_gettop(L) == 3);

#if LUA_VERSION_NUM < 502
    // lua_compare() was added in 5.2, so we have to use lua_equal() here.
    CHECK_MESSAGE(
        lua_equal(L, 2, 3) == 1,
        "Context metatable doesn't match the expected one."
    );
#else
    CHECK_MESSAGE(
        lua_compare(L, 2, 3, LUA_OPEQ) == 1,
        "Context metatable doesn't match the expected one."
    );
#endif
}


TEST_CASE_FIXTURE(AutoclosingEngineFixture, "Test closing a context") {
    Context *context = uclua_engine->create_context_in_lua();
    CHECK_NE(context, nullptr);

    // The pointer in the Lua userdata must be identical to the pointer we got
    // back from the function.
    auto userdata = reinterpret_cast<Context **>(lua_touserdata(L, -1));
    REQUIRE(*userdata == context);

    ul_context_free(L);
    CHECK(context->is_free());
}


TEST_CASE_FIXTURE(AutoclosingEngineFixture, "Closing a closed context explodes.") {
    Context *context = uclua_engine->create_context_in_lua();
    CHECK_FALSE(context->is_free());

    ul_context_free(L);
    REQUIRE(context->is_free());
    CHECK_THROWS_AS(ul_context_free(L), LuaBindingError);
}


TEST_CASE_FIXTURE(AutoclosingEngineFixture, "ul_context_maybe_free is idempotent.") {
    Context *context = uclua_engine->create_context_in_lua();
    CHECK_NE(context, nullptr);

    // The pointer in the Lua userdata must be identical to the pointer we got
    // back from the function.
    auto userdata = reinterpret_cast<Context **>(lua_touserdata(L, -1));
    REQUIRE(*userdata == context);

    ul_context_maybe_free(L);
    REQUIRE(context->is_free());

    // Nothing should happen
    ul_context_maybe_free(L);
    CHECK(context->is_free());
}



TEST_CASE_FIXTURE(AutoclosingEngineFixture, "Trying to restore from a closed context explodes.") {
    Context *context = uclua_engine->create_context_in_lua();
    CHECK_NE(context, nullptr);

    ul_context_free(L);
    CHECK(context->is_free());

    auto userdata = reinterpret_cast<Context **>(lua_touserdata(L, -1));
    CHECK_EQ(*userdata, context);
    CHECK_THROWS_AS(uclua_engine->restore_from_context(context), LuaBindingError);
}
