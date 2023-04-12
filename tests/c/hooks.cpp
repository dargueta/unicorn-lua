#include "unicornlua/hooks.h"
#include "doctest.h"
#include "fixtures.h"
#include "unicornlua/lua.h"

TEST_CASE_FIXTURE(AutoclosingEngineFixture, "Empty Hook created as expected")
{
    Hook* hook = uclua_engine->create_empty_hook();

    CHECK_MESSAGE(hook->get_callback() == LUA_NOREF,
        "Hook callback should be undefined.");
    CHECK_MESSAGE(hook->get_user_data() == LUA_REFNIL,
        "User data bound to hook should be nil by default.");
    CHECK_MESSAGE(
        hook->get_hook_handle() == 0, "Hook handle should be 0 by default.");
}
