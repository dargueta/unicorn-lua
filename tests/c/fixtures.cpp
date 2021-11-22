#include <sstream>

#include <unicorn/unicorn.h>

#include "doctest.h"
#include "fixtures.h"
#include "unicornlua/engine.h"
#include "unicornlua/lua.h"


LuaFixture::LuaFixture() {
    L = luaL_newstate();
}


LuaFixture::~LuaFixture() {
    // The test may close the state for us in a couple cases where we deliberately
    // trigger a panic, since the state is no longer valid.
    if (L == nullptr)
        return;

    CHECK_MESSAGE(lua_gettop(L) == 0, "Garbage left on the stack after test exited.");
    if (lua_gettop(L) > 0) {
        std::ostringstream buf;
        for (int i = 1; i <= lua_gettop(L); ++i) {
            const char *type_name = lua_typename(L, i);
            buf << "At stack index " << i << ": " << type_name << "\n";
        }
        FAIL(buf.str().c_str());
    }
    lua_close(L);
}


EngineFixture::EngineFixture() : LuaFixture(), uclua_engine(nullptr)
{
    ul_init_engines_lib(L);
    REQUIRE_MESSAGE(lua_gettop(L) == 0, "Garbage left on the stack.");

    uc_engine *engine_handle;
    uc_err error = uc_open(UC_ARCH_X86, UC_MODE_32, &engine_handle);
    REQUIRE_MESSAGE(error == UC_ERR_OK, "Failed to create an x86-32 engine.");

    uclua_engine = new UCLuaEngine(L, engine_handle);
    REQUIRE(uclua_engine->get_handle() != nullptr);
    REQUIRE(lua_gettop(L) == 0);
}


AutoclosingEngineFixture::~AutoclosingEngineFixture() {
    // This REQUIRE shouldn't be necessary but we're getting segfaults in LuaJIT
    // but only on OSX. I'm at my wits' end trying to figure this out.
    REQUIRE(L != nullptr);
    delete uclua_engine;
}
