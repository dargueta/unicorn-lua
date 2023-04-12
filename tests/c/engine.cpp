#include <unicorn/unicorn.h>

#include "doctest.h"
#include "fixtures.h"
#include "unicornlua/context.h"
#include "unicornlua/errors.h"
#include "unicornlua/lua.h"

TEST_CASE_FIXTURE(
    EngineFixture, "UCLuaEngine::close() sets engine handle to null")
{
    uclua_engine->close();
    CHECK_MESSAGE(uclua_engine->get_handle() == nullptr,
        "Engine handle should be null after closing.");
}

TEST_CASE_FIXTURE(
    EngineFixture, "UCLuaEngine::close() crashes if you call it twice")
{
    uclua_engine->close();
    CHECK_MESSAGE(uclua_engine->get_handle() == nullptr,
        "Engine handle should be null after closing.");
    CHECK_THROWS_AS(uclua_engine->close(), LuaBindingError);
}

TEST_CASE_FIXTURE(
    AutoclosingEngineFixture, "UCLuaEngine::query() generally works")
{
    CHECK_EQ(uclua_engine->query(UC_QUERY_PAGE_SIZE), 4096);
}

TEST_CASE_FIXTURE(AutoclosingEngineFixture,
    "UCLuaEngine::query() raises exception when given a bad query type")
{
    CHECK_THROWS_AS(
        uclua_engine->query((uc_query_type)-123), UnicornLibraryError);
}

TEST_CASE_FIXTURE(AutoclosingEngineFixture, "errno() on clean engine works")
{
    // We haven't done anything with the engine so its status should be fine.
    CHECK_EQ(uclua_engine->get_errno(), UC_ERR_OK);
}

// TODO (dargueta): Force the engine into a bad state to verify ::get_errno()
