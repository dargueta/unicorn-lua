#include <unicorn/unicorn.h>

#include "unicornlua/common.h"
#include "unicornlua/lua.h"


static const struct NamedIntConst kM68KConstants[] = {
    {"UC_M68K_REG_INVALID", UC_M68K_REG_INVALID},
    {"UC_M68K_REG_A0", UC_M68K_REG_A0},
    {"UC_M68K_REG_A1", UC_M68K_REG_A1},
    {"UC_M68K_REG_A2", UC_M68K_REG_A2},
    {"UC_M68K_REG_A3", UC_M68K_REG_A3},
    {"UC_M68K_REG_A4", UC_M68K_REG_A4},
    {"UC_M68K_REG_A5", UC_M68K_REG_A5},
    {"UC_M68K_REG_A6", UC_M68K_REG_A6},
    {"UC_M68K_REG_A7", UC_M68K_REG_A7},
    {"UC_M68K_REG_D0", UC_M68K_REG_D0},
    {"UC_M68K_REG_D1", UC_M68K_REG_D1},
    {"UC_M68K_REG_D2", UC_M68K_REG_D2},
    {"UC_M68K_REG_D3", UC_M68K_REG_D3},
    {"UC_M68K_REG_D4", UC_M68K_REG_D4},
    {"UC_M68K_REG_D5", UC_M68K_REG_D5},
    {"UC_M68K_REG_D6", UC_M68K_REG_D6},
    {"UC_M68K_REG_D7", UC_M68K_REG_D7},
    {"UC_M68K_REG_SR", UC_M68K_REG_SR},
    {"UC_M68K_REG_PC", UC_M68K_REG_PC},
    {"UC_M68K_REG_ENDING", UC_M68K_REG_ENDING},

    {NULL, 0}
};


int luaopen_unicorn_m68k(lua_State *L) {
    lua_newtable(L);
    load_int_constants(L, kM68KConstants);
    return 1;
}
