#include "unicornlua/utils.h"
#include <lua.h>
#include <unicorn/unicorn.h>

int ul_context_save(lua_State *L)
{
    uc_engine *engine = (uc_engine *)lua_topointer(L, 1);
    uc_context *context;

    uc_err error = uc_context_alloc(engine, &context);
    ulinternal_crash_if_failed(L, error, "Can't allocate memory to save engine state.");

    error = uc_context_save(engine, context);
    ulinternal_crash_if_failed(L, error, "Can't save engine state.");

    lua_pushlightuserdata(L, context);
    return 1;
}

int ul_context_save_reuse_existing(lua_State *L)
{
    uc_engine *engine = (uc_engine *)lua_topointer(L, 1);
    uc_context *context = (uc_context *)lua_topointer(L, 2);

    uc_err error = uc_context_save(engine, context);
    ulinternal_crash_if_failed(L, error, "Can't save engine state with reused context.");
    return 1;
}

int ul_context_restore(lua_State *L)
{
    uc_engine *engine = (uc_engine *)lua_topointer(L, 1);
    uc_context *context = (uc_context *)lua_topointer(L, 2);

    uc_err error = uc_context_restore(engine, context);
    ulinternal_crash_if_failed(L, error, "Can't restore engine state.");
    return 0;
}

int ul_context_free(lua_State *L)
{
    uc_context *context = (uc_context *)lua_topointer(L, 1);

    uc_err error = uc_context_free(context);
    ulinternal_crash_if_failed(L, error, "Failed to deallocate engine context.");
    return 0;
}
