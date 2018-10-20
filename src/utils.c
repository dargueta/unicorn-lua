#include <stdlib.h>

#include <lauxlib.h>
#include <lua.h>
#include <unicorn/unicorn.h>

extern const char *kEngineMetatableName;
extern const char *kContextMetatableName;


/** TODO (dargueta): Make this attribute work on Microsoft compilers. */
int uc_lua__crash_on_error(lua_State *L, int error) {
    const char *message;

    message = uc_strerror(error);
    lua_pushstring(L, message);
    return lua_error(L);
}


uc_engine *uc_lua__toengine(lua_State *L, int index) {
    uc_engine *engine;

    engine = *(uc_engine **)luaL_checkudata(L, index, kEngineMetatableName);
    if (engine == NULL)
        luaL_error(L, "Attempted to use closed engine.");
    return engine;
}


uc_context *uc_lua__tocontext(lua_State *L, int index) {
    uc_context *context;

    context = *(uc_context **)luaL_checkudata(L, index, kContextMetatableName);
    if (context == NULL)
        luaL_error(L, "Attempted to use closed context.");
    return context;
}


void *uc_lua__realloc(lua_State *L, void *ptr, size_t new_size) {
    void *tmp = realloc(ptr, new_size);
    if (tmp == NULL) {
        luaL_error(L, "Out of memory.");
        return NULL;
    }
    return tmp;
}
