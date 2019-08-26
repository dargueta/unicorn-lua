#ifndef INCLUDE_UNICORNLUA_COMMON_H_
#define INCLUDE_UNICORNLUA_COMMON_H_

#include "unicornlua/lua.h"

struct NamedIntConst {
    const char *name;
    lua_Integer value;
};


int load_int_constants(lua_State *L, const struct NamedIntConst *constants);


#endif  /* INCLUDE_UNICORNLUA_COMMON_H_ */
