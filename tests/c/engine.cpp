#include <memory>

#include "doctest.h"
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
        // Don't close engine_handle and uclua_engine since we
        lua_close(L);
    }

    uc_engine *engine_handle;
    UCLuaEngine *uclua_engine;
    lua_State *L;
};


class AutoclosingEngineFixture : public EngineFixture {
public:
    ~AutoclosingEngineFixture() {
        // Don't close engine_handle since the uclua_engine will get it for us.
        if (uclua_engine != nullptr)
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
