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
    uc_err error;

    if (handle_ == nullptr)
        throw LuaBindingError("Attempted to close already-closed context.");

#if UNICORNLUA_UNICORN_MAJOR_MINOR_PATCH >= 0x010002
    /* Unicorn 1.0.2 added its own separate function for freeing contexts. */
    error = uc_context_free(handle_);
#else
    /* Unicorn 1.0.1 and lower uses uc_free(). */
    error = uc_free(handle_);
#endif

    handle_ = nullptr;
    if (error != UC_ERR_OK)
        throw UnicornLibraryError(error);
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
        Context *context = get_context_struct(L, 2);
        if (context->is_free())
            throw LuaBindingError("Cannot update a closed context.");
        context->update();
    }
    return 1;
}


int ul_context_restore(lua_State *L) {
    auto engine = get_engine_struct(L, 1);
    Context *context = get_context_struct(L, 2);

    if (context->is_free())
        throw LuaBindingError("Cannot restore from a closed context.");

    engine->restore_from_context(context);
    return 0;
}


int ul_context_free(lua_State *L) {
    Context *context = get_context_struct(L, 1);
    context->free();
    return 0;
}


int ul_context_maybe_free(lua_State *L) {
    Context *context = get_context_struct(L, 1);

    // Do nothing if the context has already been freed.
    if (!context->is_free())
        return ul_context_free(L);
    return 0;
}
