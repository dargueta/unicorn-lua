#include <unicorn/unicorn.h>

#include "unicornlua/errors.h"
#include "unicornlua/engine.h"
#include "unicornlua/context.h"
#include "unicornlua/utils.h"


const char * const kContextMetatableName = "unicornlua__context_meta";


static int call_release(lua_State *L) {
    Context *context = get_context_struct(L, 1);
    if (!context->is_released())
        context->release();
    return 0;
}


const luaL_Reg kContextMetamethods[] = {
    {"__gc", call_release},
    {"__close", call_release},
    {nullptr, nullptr}
};


const luaL_Reg kContextInstanceMethods[] = {
    {"free", call_release},
    {nullptr, nullptr}
};


Context::Context(UCLuaEngine& engine, uc_context *context)
    : engine_(engine), context_(context) {}


Context::Context(UCLuaEngine& engine)
    : engine_(engine), context_(nullptr) {}


Context::~Context() {
    if (context_ != nullptr)
        release();
}


uc_context *Context::get_handle() const noexcept { return context_; }


void Context::update() {
    uc_err error;

    if (context_ == nullptr) {
        error = uc_context_alloc(engine_.engine, &context_);
        if (error != UC_ERR_OK)
            throw UnicornLibraryError(error);
    }

    error = uc_context_save(engine_.engine, context_);
    if (error != UC_ERR_OK)
        throw UnicornLibraryError(error);
}


void Context::release() {
    uc_err error;

    if (context_ == nullptr)
        throw LuaBindingError(
            "Attempted to free a context object that has already been freed."
        );

    #if UNICORNLUA_UNICORN_MAJOR_MINOR_PATCH >= 0x010002
        /* Unicorn 1.0.2 added its own separate function for freeing contexts. */
        error = uc_context_free(context_);
    #else
        /* Unicorn 1.0.1 and lower uses uc_free(). */
        error = uc_free(context_);
    #endif

    context_ = nullptr;
    if (error != UC_ERR_OK)
        throw UnicornLibraryError(error);
}


bool Context::is_released() const noexcept {
    return context_ == nullptr;
}


int ul_context_save(lua_State *L) {
    auto engine = get_engine_struct(L, 1);
    Context *context;

    if (lua_gettop(L) < 2) {
        // Caller didn't provide a context, create a new one and push it to the stack
        // so we can return it to the caller.
        context = engine->create_context_in_lua();
    }
    else {
        context = get_context_struct(L, 2);
        context->update();
    }
    return 1;
}


int ul_context_restore(lua_State *L) {
    auto engine = get_engine_struct(L, 1);
    auto context = get_context_struct(L, 2);

    engine->restore_from_context(context);
    return 0;
}


int ul_context_free(lua_State *L) {
    auto context = get_context_struct(L, 1);

    context->release();
    return 0;
}
