#include <unicorn/unicorn.h>

#include "unicornlua/engine.h"
#include "unicornlua/context.h"
#include "unicornlua/utils.h"


Context::Context(UCLuaEngine& engine, uc_context *context)
    : engine_(engine), context_(context) {}


Context::Context(UCLuaEngine& engine)
    : engine_(engine), context_(nullptr) {}


Context::~Context() {
    if (context_)
        release();
}


uc_context *Context::get_handle() const noexcept { return context_; }


void Context::update() {
    uc_err error;

    if (!context_) {
        error = uc_context_alloc(engine_.engine, &context_);
        if (error != UC_ERR_OK) {
            ul_crash_on_error(engine_.L, error);
            return;
        }
    }

    error = uc_context_save(engine_.engine, context_);
    if (error != UC_ERR_OK) {
        ul_crash_on_error(engine_.L, error);
        return;
    }
}


void Context::release() {
    uc_err error = uc_free(context_);
    context_ = nullptr;
    if (error != UC_ERR_OK) {
        ul_crash_on_error(engine_.L, error);
        return;
    }
}


bool Context::is_released() const noexcept {
    return context_ == nullptr;
}




int ul_context_alloc(lua_State *L) {
    uc_engine *engine = ul_toengine(L, 1);
    uc_context *context = (uc_context *)lua_newuserdata(L, sizeof(context));
    luaL_setmetatable(L, kContextMetatableName);

    uc_err error = uc_context_alloc(engine, &context);
    if (error != UC_ERR_OK)
        return ul_crash_on_error(L, error);

    return 1;
}


int ul_context_save(lua_State *L) {
    auto engine = get_engine_struct(L, 1);
    Context *context;

    if (lua_gettop(L) < 2) {
        // Caller didn't provide a context, create a new one and push it to the stack
        // so we can return it to the caller.
        context = engine->create_context();
        lua_pushlightuserdata(L, context);
    }
    else
        context = (Context *)lua_topointer(L, 2);

    context->update();
    return 1;
}


int ul_context_restore(lua_State *L) {
    auto engine = get_engine_struct(L, 1);
    auto context = (Context *)lua_topointer(L, 2);

    engine->restore_from_context(context);
    return 0;
}
