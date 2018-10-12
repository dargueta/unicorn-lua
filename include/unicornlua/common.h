#ifndef INCLUDE_UNICORNLUA_COMMON_H_
#define INCLUDE_UNICORNLUA_COMMON_H_

#include <lua.h>

struct NamedIntConst {
    const char *name;
    lua_Integer value;
};

#endif  /* INCLUDE_UNICORNLUA_COMMON_H_ */
