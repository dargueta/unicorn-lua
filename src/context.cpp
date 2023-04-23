#include "unicornlua/context.hpp"
#include "unicornlua/engine.hpp"
#include "unicornlua/errors.hpp"
#include "unicornlua/lua.hpp"

const char* const kContextMetatableName = "unicornlua__context_meta";

constexpr luaL_Reg kContextMetamethods[] = { { "__gc", ul_context_maybe_free },
    { "__close", ul_context_maybe_free }, { nullptr, nullptr } };

constexpr luaL_Reg kContextInstanceMethods[]
    = { { "free", ul_context_free }, { nullptr, nullptr } };

Context* ul_toluacontext(lua_State* L, int index)
{
    return reinterpret_cast<Context*>(
        luaL_checkudata(L, index, kContextMetatableName));
}

int ul_context_save(lua_State* L)
{
    UCLuaEngine* engine = ul_toluaengine(L, 1);

    if (lua_gettop(L) < 2) {
        // Caller didn't provide a context, create a new one and push it to the
        // stack so we can return it to the caller.
        engine->create_context_in_lua();
    } else {
        Context* context = ul_toluacontext(L, 2);
        if (context->context_handle == nullptr)
            throw LuaBindingError("Cannot update a closed context.");

        context->engine->update_context(context);
    }
    return 1;
}

int ul_context_restore(lua_State* L)
{
    UCLuaEngine* engine = ul_toluaengine(L, 1);
    Context* context = ul_toluacontext(L, 2);
    engine->restore_from_context(context);
    return 0;
}

int ul_context_free(lua_State* L)
{
    Context* context = ul_toluacontext(L, 1);

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
    Context* context = ul_toluacontext(L, 1);

    // Do nothing if the context has already been freed.
    if (context->context_handle != nullptr)
        ul_context_free(L);
    return 0;
}
