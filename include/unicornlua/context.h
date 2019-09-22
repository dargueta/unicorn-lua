/**
 * Lua bindings for Unicorn context operations.
 *
 * @file context.h
 */

#ifndef INCLUDE_UNICORNLUA_CONTEXT_H_
#define INCLUDE_UNICORNLUA_CONTEXT_H_

#include <unicorn/unicorn.h>

#include "unicornlua/engine.h"
#include "unicornlua/lua.h"

extern const char * const kContextMetatableName;
extern const luaL_Reg kContextMetamethods[];


class Context {
    friend class UCLuaEngine;

protected:
    Context(UCLuaEngine& engine);
    Context(UCLuaEngine& engine, uc_context *context);

public:
    ~Context();

    void update();
    void release();
    bool is_released() const noexcept;
    uc_context *get_handle() const noexcept;

private:
    UCLuaEngine& engine_;
    uc_context *context_;
};


int ul_context_save(lua_State *L);
int ul_context_restore(lua_State *L);


#define get_context_struct(L, index)   \
    reinterpret_cast<Context *>(luaL_checkudata((L), (index), kContextMetatableName))

#endif  /* INCLUDE_UNICORNLUA_CONTEXT_H_ */
