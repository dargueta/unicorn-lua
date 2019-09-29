#include <unicorn/unicorn.h>

#include "doctest.h"
#include "unicornlua/context.h"
#include "unicornlua/engine.h"
#include "unicornlua/errors.h"
#include "unicornlua/lua.h"


class EngineFixture {
public:
    EngineFixture() : engine_handle(nullptr), uclua_engine(nullptr), L(nullptr) {
        L = luaL_newstate();

        uc_err error = uc_open(UC_ARCH_MIPS, UC_MODE_32, &engine_handle);
        REQUIRE_MESSAGE(error == UC_ERR_OK, "Failed to create a MIPS engine.");

        uclua_engine = new UCLuaEngine(L, engine_handle);
        REQUIRE(uclua_engine->L != nullptr);
        REQUIRE(uclua_engine->engine != nullptr);
    }

    virtual ~EngineFixture() {
        lua_close(L);
    }

    uc_engine *engine_handle;
    UCLuaEngine *uclua_engine;
    lua_State *L;
};


class AutoclosingEngineFixture : public EngineFixture {
public:
    ~AutoclosingEngineFixture() override {
        // Don't close engine_handle since the uclua_engine will get it for us.
        delete uclua_engine;
    }
};


TEST_CASE_FIXTURE(EngineFixture, "UCLuaEngine::close() sets engine handle to null") {
    uclua_engine->close();
    CHECK_MESSAGE(
        uclua_engine->engine == nullptr,
        "Engine handle should be null after closing."
    );
}

TEST_CASE_FIXTURE(EngineFixture, "UCLuaEngine::close() crashes if you call it twice") {
    uclua_engine->close();
    CHECK_MESSAGE(
        uclua_engine->engine == nullptr,
        "Engine handle should be null after closing."
    );
    CHECK_THROWS_AS(uclua_engine->close(), LuaBindingError);
}


TEST_CASE_FIXTURE(AutoclosingEngineFixture, "UCLuaEngine::query() generally works") {
    CHECK_EQ(uclua_engine->query(UC_QUERY_PAGE_SIZE), 4096);
}


TEST_CASE_FIXTURE(
    AutoclosingEngineFixture,
    "UCLuaEngine::query() raises exception when given a bad query type"
) {
    CHECK_THROWS_AS(uclua_engine->query(UC_QUERY_MODE), UnicornLibraryError);
}


TEST_CASE_FIXTURE(AutoclosingEngineFixture, "errno() on clean engine works") {
    // We haven't done anything with the engine so its status should be fine.
    CHECK_EQ(uclua_engine->get_errno(), UC_ERR_OK);
}

// TODO (dargueta): Force the engine into a bad state to verify ::get_errno()


TEST_CASE_FIXTURE(AutoclosingEngineFixture, "Test creating a context") {
    REQUIRE_MESSAGE(lua_gettop(L) == 0, "The Lua stack should be empty.");

    Context *context = uclua_engine->create_context_in_lua();
    REQUIRE_NE(context, nullptr);

    REQUIRE_MESSAGE(
        lua_gettop(L) == 1, "Expecting a context object on the stack."
    );
    REQUIRE_MESSAGE(
        lua_type(L, 1) == LUA_TUSERDATA, "Object at top of stack should be userdata."
    );

    REQUIRE_MESSAGE(
        lua_touserdata(L, 1) == context,
        "TOS isn't the context object we were expecting."
    );

    // Metatable of the context is at index 2, the expected metatable is at index 3.
    REQUIRE_MESSAGE(
        lua_getmetatable(L, 1) != 0, "Context object has no metatable."
    );
    luaL_getmetatable(L, kContextMetatableName);

    /*
    CHECK_MESSAGE(
        lua_compare(L, 2, 3, LUA_OPEQ) == 1,
        "Context metatable doesn't match the expected one."
    );
     */
}
