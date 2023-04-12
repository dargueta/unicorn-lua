#include <unicorn/unicorn.h>

#include "unicornlua/context.h"
#include "unicornlua/engine.h"
#include "unicornlua/errors.h"
#include "unicornlua/utils.h"

const char* const kContextMetatableName = "unicornlua__context_meta";

const luaL_Reg kContextMetamethods[] = { { "__gc", ul_context_maybe_free },
    { "__close", ul_context_maybe_free }, { nullptr, nullptr } };

const luaL_Reg kContextInstanceMethods[]
    = { { "free", ul_context_free }, { nullptr, nullptr } };

int ul_context_save(lua_State* L)
{
    auto engine = get_engine_struct(L, 1);

    if (lua_gettop(L) < 2) {
        // Caller didn't provide a context, create a new one and push it to the
        // stack so we can return it to the caller.
        engine->create_context_in_lua();
    } else {
        Context* context = get_context_struct(L, 2);
        if (context->context_handle == nullptr)
            throw LuaBindingError("Cannot update a closed context.");

        context->engine->update_context(context);
    }
    return 1;
}

int ul_context_restore(lua_State* L)
{
    auto engine = get_engine_struct(L, 1);
    Context* context = get_context_struct(L, 2);
    engine->restore_from_context(context);
    return 0;
}

int ul_context_free(lua_State* L)
{
    Context* context = get_context_struct(L, 1);

    if (context->context_handle == nullptr)
        throw LuaBindingError("Attempted to free the same context twice.");
    if (context->engine == nullptr)
        throw LuaBindingError("BUG: Engine was collected before the context.");

    context->engine->free_context(context);
    context->context_handle = nullptr;
    context->engine = nullptr;
    return 0;
}

int ul_context_maybe_free(lua_State* L)
{
    Context* context = get_context_struct(L, 1);

    // Do nothing if the context has already been freed.
    if (context->context_handle != nullptr)
        ul_context_free(L);
    return 0;
}
