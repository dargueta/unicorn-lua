#ifndef INCLUDE_TESTS_C_FIXTURES_H_
#define INCLUDE_TESTS_C_FIXTURES_H_

#include <unicorn/unicorn.h>

#include "unicornlua/engine.hpp"
#include "unicornlua/lua.hpp"

class LuaFixture {
public:
    LuaFixture();
    virtual ~LuaFixture();

    lua_State* L;
};

class EngineFixture : public LuaFixture {
public:
    EngineFixture();

    UCLuaEngine* uclua_engine;
};

class AutoclosingEngineFixture : public EngineFixture {
public:
    ~AutoclosingEngineFixture() override;
};

#endif // INCLUDE_TESTS_C_FIXTURES_H_
