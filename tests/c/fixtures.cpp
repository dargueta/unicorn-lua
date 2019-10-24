#include <unicorn/unicorn.h>

#include "doctest.h"
#include "fixtures.h"
#include "unicornlua/engine.h"
#include "unicornlua/lua.h"


LuaFixture::LuaFixture() {
    L = luaL_newstate();
}


LuaFixture::~LuaFixture() {
    lua_close(L);
}


EngineFixture::EngineFixture()
    : LuaFixture(), engine_handle(nullptr), uclua_engine(nullptr)
{
    ul_init_engines_lib(L);
    REQUIRE_MESSAGE(lua_gettop(L) == 0, "Garbage left on the stack.");

    uc_err error = uc_open(UC_ARCH_MIPS, UC_MODE_32, &engine_handle);
    REQUIRE_MESSAGE(error == UC_ERR_OK, "Failed to create a MIPS engine.");

    uclua_engine = new UCLuaEngine(L, engine_handle);
    REQUIRE(uclua_engine->L != nullptr);
    REQUIRE(uclua_engine->engine != nullptr);
    REQUIRE(lua_gettop(L) == 0);
}


AutoclosingEngineFixture::~AutoclosingEngineFixture() {
    // Don't close engine_handle since the uclua_engine will get it for us.
    delete uclua_engine;
}
