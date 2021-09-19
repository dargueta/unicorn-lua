#include <unicorn/unicorn.h>

#include "unicornlua/lua.h"
#include "unicornlua/registers.h"
#include "unicornlua/utils.h"


static const struct NamedIntConst kConstants[] {
    {"REG_TYPE_INT8", RegisterDataType::UL_REG_TYPE_INT8},
    {"REG_TYPE_INT16", RegisterDataType::UL_REG_TYPE_INT16},
    {"REG_TYPE_INT32", RegisterDataType::UL_REG_TYPE_INT32},
    {"REG_TYPE_FLOAT32", RegisterDataType::UL_REG_TYPE_FLOAT32},
    {"REG_TYPE_INT64", RegisterDataType::UL_REG_TYPE_INT64},
    {"REG_TYPE_FLOAT64", RegisterDataType::UL_REG_TYPE_FLOAT64},
    {"REG_TYPE_INT8_ARRAY_8", RegisterDataType::UL_REG_TYPE_INT8_ARRAY_8},
    {"REG_TYPE_INT16_ARRAY_4", RegisterDataType::UL_REG_TYPE_INT16_ARRAY_4},
    {"REG_TYPE_INT32_ARRAY_2", RegisterDataType::UL_REG_TYPE_INT32_ARRAY_2},
    {"REG_TYPE_INT64_ARRAY_1", RegisterDataType::UL_REG_TYPE_INT64_ARRAY_1},
    {"REG_TYPE_FLOAT80", RegisterDataType::UL_REG_TYPE_FLOAT80},
    {"REG_TYPE_INT8_ARRAY_16", RegisterDataType::UL_REG_TYPE_INT8_ARRAY_16},
    {"REG_TYPE_INT16_ARRAY_8", RegisterDataType::UL_REG_TYPE_INT16_ARRAY_8},
    {"REG_TYPE_INT32_ARRAY_4", RegisterDataType::UL_REG_TYPE_INT32_ARRAY_4},
    {"REG_TYPE_INT64_ARRAY_2", RegisterDataType::UL_REG_TYPE_INT64_ARRAY_2},
    {"REG_TYPE_FLOAT32_ARRAY_4", RegisterDataType::UL_REG_TYPE_FLOAT32_ARRAY_4},
    {"REG_TYPE_FLOAT64_ARRAY_2", RegisterDataType::UL_REG_TYPE_FLOAT64_ARRAY_2},
    {"REG_TYPE_INT8_ARRAY_32", RegisterDataType::UL_REG_TYPE_INT8_ARRAY_32},
    {"REG_TYPE_INT16_ARRAY_16", RegisterDataType::UL_REG_TYPE_INT16_ARRAY_16},
    {"REG_TYPE_INT32_ARRAY_8", RegisterDataType::UL_REG_TYPE_INT32_ARRAY_8},
    {"REG_TYPE_INT64_ARRAY_4", RegisterDataType::UL_REG_TYPE_INT64_ARRAY_4},
    {"REG_TYPE_FLOAT32_ARRAY_8", RegisterDataType::UL_REG_TYPE_FLOAT32_ARRAY_8},
    {"REG_TYPE_FLOAT64_ARRAY_4", RegisterDataType::UL_REG_TYPE_FLOAT64_ARRAY_4},
    {"REG_TYPE_INT8_ARRAY_64", RegisterDataType::UL_REG_TYPE_INT8_ARRAY_64},
    {"REG_TYPE_INT16_ARRAY_32", RegisterDataType::UL_REG_TYPE_INT16_ARRAY_32},
    {"REG_TYPE_INT32_ARRAY_16", RegisterDataType::UL_REG_TYPE_INT32_ARRAY_16},
    {"REG_TYPE_INT64_ARRAY_8", RegisterDataType::UL_REG_TYPE_INT64_ARRAY_8},
    {"REG_TYPE_FLOAT32_ARRAY_16", RegisterDataType::UL_REG_TYPE_FLOAT32_ARRAY_16},
    {"REG_TYPE_FLOAT64_ARRAY_8", RegisterDataType::UL_REG_TYPE_FLOAT64_ARRAY_8},

    {nullptr, 0}
};


extern "C" UNICORN_EXPORT int luaopen_unicorn_registers_const(lua_State *L) {
    lua_createtable(L, 0, 28);
    load_int_constants(L, kConstants);
    return 1;
}
