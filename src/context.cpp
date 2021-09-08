#include <unicorn/unicorn.h>

#include "unicornlua/errors.h"
#include "unicornlua/engine.h"
#include "unicornlua/context.h"
#include "unicornlua/utils.h"


const char * const kContextMetatableName = "unicornlua__context_meta";


const luaL_Reg kContextMetamethods[] = {
    {"__gc", ul_context_maybe_free},
    {"__close", ul_context_maybe_free},
    {nullptr, nullptr}
};


const luaL_Reg kContextInstanceMethods[] = {
    {"free", ul_context_free},
    {nullptr, nullptr}
};


Context::Context(UCLuaEngine &engine, uc_context *handle)
    : engine_(engine), handle_(handle)
{}


Context::~Context() noexcept(false) {
    if (handle_ != nullptr)
        free();
}


uc_context *Context::get_handle() const noexcept { return handle_; }


void Context::update() {
    uc_err error;
    uc_engine *engine = engine_.get_handle();

    if (handle_ == nullptr) {
        error = uc_context_alloc(engine, &handle_);
        if (error != UC_ERR_OK)
            throw UnicornLibraryError(error);
    }

    error = uc_context_save(engine, handle_);
    if (error != UC_ERR_OK)
        throw UnicornLibraryError(error);
}

void Context::free() {
    engine_.remove_context(this);
    handle_ = nullptr;
}


bool Context::is_free() const noexcept { return handle_ == nullptr; }


int ul_context_save(lua_State *L) {
    auto engine = get_engine_struct(L, 1);

    if (lua_gettop(L) < 2) {
        // Caller didn't provide a context, create a new one and push it to the stack
        // so we can return it to the caller.
        engine->create_context_in_lua();
    }
    else {
        Context **p_context = get_context_struct(L, 2);
        if (*p_context == nullptr || (*p_context)->is_free())
            throw LuaBindingError("Cannot update a closed context.");

        (*p_context)->update();
    }
    return 1;
}


int ul_context_restore(lua_State *L) {
    auto engine = get_engine_struct(L, 1);
    Context **p_context = get_context_struct(L, 2);

    if (*p_context == nullptr || (*p_context)->is_free())
        throw LuaBindingError("Cannot restore from a closed context.");

    engine->restore_from_context(*p_context);
    return 0;
}


int ul_context_free(lua_State *L) {
    Context **p_context = get_context_struct(L, 1);
    if (*p_context == nullptr || (*p_context)->is_free())
        throw LuaBindingError("Cannot close a closed context.");

    (*p_context)->free();
    *p_context = nullptr;
    return 0;
}


int ul_context_maybe_free(lua_State *L) {
    Context **p_context = get_context_struct(L, 1);

    // Do nothing if the context has already been freed.
    if (*p_context != nullptr && !(*p_context)->is_free())
        (*p_context)->free();

    *p_context = nullptr;
    return 0;
}
