#include <unicorn/unicorn.h>

#include "doctest.h"
#include "fixtures.h"
#include "unicornlua/context.h"
#include "unicornlua/engine.h"
#include "unicornlua/errors.h"


TEST_CASE_FIXTURE(AutoclosingEngineFixture, "Test creating a context") {
    Context *context = uclua_engine->create_context_in_lua();
    CHECK_NE(context, nullptr);
    CHECK(!context->is_released());

    CHECK_MESSAGE(
        lua_gettop(L) == 1, "Expecting a context object on the stack."
    );
    CHECK_MESSAGE(
        lua_type(L, 1) == LUA_TUSERDATA, "Object at top of stack should be userdata."
    );

    CHECK_MESSAGE(
        lua_touserdata(L, 1) == context,
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
    REQUIRE(!context->is_released());

    context->release();
    REQUIRE(context->is_released());
}


TEST_CASE_FIXTURE(AutoclosingEngineFixture, "Closing a closed context explodes.") {
    Context *context = uclua_engine->create_context_in_lua();
    CHECK_NE(context, nullptr);
    REQUIRE(!context->is_released());

    context->release();
    REQUIRE(context->is_released());
    CHECK_THROWS_AS(context->release(), LuaBindingError);
}


TEST_CASE_FIXTURE(AutoclosingEngineFixture, "Trying to restore from a closed context explodes.") {
    Context *context = uclua_engine->create_context_in_lua();
    CHECK_NE(context, nullptr);
    REQUIRE(!context->is_released());

    context->release();
    REQUIRE(context->is_released());
    CHECK_THROWS_AS(uclua_engine->restore_from_context(context), LuaBindingError);
}
