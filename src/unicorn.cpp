extern "C" {
#include <lua.h>
}
#include <unicorn/unicorn.h>

#include "unicornlua/common.h"
#include "unicornlua/engine.h"
#include "unicornlua/utils.h"


int ul_version(lua_State *L) {
    unsigned major, minor;

    uc_version(&major, &minor);
    lua_pushinteger(L, major);
    lua_pushinteger(L, minor);
    return 2;
}


int ul_arch_supported(lua_State *L) {
    auto architecture = static_cast<uc_arch>(luaL_checkinteger(L, -1));
    lua_pushboolean(L, uc_arch_supported(architecture));
    return 1;
}


int ul_open(lua_State *L) {
    auto architecture = static_cast<uc_arch>(luaL_checkinteger(L, 1));
    auto mode = static_cast<uc_mode>(luaL_checkinteger(L, 2));

    uc_engine *engine;
    uc_err error = uc_open(architecture, mode, &engine);
    if (error != UC_ERR_OK)
        return ul_crash_on_error(L, error);

    ul_create_engine_object(L, engine);
    return 1;
}


int ul_strerror(lua_State *L) {
    auto error = static_cast<uc_err>(luaL_checkinteger(L, 1));
    lua_pushstring(L, uc_strerror(error));
    return 1;
}


int ul_free(lua_State *L) {
    uc_err error = uc_free(*(void **)lua_touserdata(L, 1));
    if (error != UC_ERR_OK)
        return ul_crash_on_error(L, error);
    return 0;
}


static const luaL_Reg kUnicornLibraryFunctions[] = {
    {"arch_supported", ul_arch_supported},
    {"open", ul_open},
    {"strerror", ul_strerror},
    {"version", ul_version},
    {nullptr, nullptr}
};


static const luaL_Reg kContextMetamethods[] = {
    {"__gc", ul_free},
    {nullptr, nullptr}
};


static const struct NamedIntConst kModuleConstants[] = {
    {"UC_API_MAJOR", UC_API_MAJOR},
    {"UC_API_MINOR", UC_API_MINOR},
    {"UC_VERSION_MAJOR", UC_VERSION_MAJOR},
    {"UC_VERSION_MINOR", UC_VERSION_MINOR},
    {"UC_VERSION_EXTRA", UC_VERSION_EXTRA},
    {"UC_SECOND_SCALE", UC_SECOND_SCALE},

    /* The typo is present in the library code. I've provided a corrected
     * version as well. */
    {"UC_MILISECOND_SCALE", UC_MILISECOND_SCALE},
    {"UC_MILLISECOND_SCALE", UC_MILISECOND_SCALE},

    {"UC_ARCH_ARM", UC_ARCH_ARM},
    {"UC_ARCH_ARM64", UC_ARCH_ARM64},
    {"UC_ARCH_MIPS", UC_ARCH_MIPS},
    {"UC_ARCH_X86", UC_ARCH_X86},
    {"UC_ARCH_PPC", UC_ARCH_PPC},
    {"UC_ARCH_SPARC", UC_ARCH_SPARC},
    {"UC_ARCH_M68K", UC_ARCH_M68K},
    {"UC_ARCH_MAX", UC_ARCH_MAX},

    {"UC_MODE_LITTLE_ENDIAN", UC_MODE_LITTLE_ENDIAN},
    {"UC_MODE_BIG_ENDIAN", UC_MODE_BIG_ENDIAN},
    {"UC_MODE_ARM", UC_MODE_ARM},
    {"UC_MODE_THUMB", UC_MODE_THUMB},
    {"UC_MODE_MCLASS", UC_MODE_MCLASS},
    {"UC_MODE_V8", UC_MODE_V8},
    {"UC_MODE_MICRO", UC_MODE_MICRO},
    {"UC_MODE_MIPS3", UC_MODE_MIPS3},
    {"UC_MODE_MIPS32R6", UC_MODE_MIPS32R6},
    {"UC_MODE_MIPS32", UC_MODE_MIPS32},
    {"UC_MODE_MIPS64", UC_MODE_MIPS64},
    {"UC_MODE_16", UC_MODE_16},
    {"UC_MODE_32", UC_MODE_32},
    {"UC_MODE_64", UC_MODE_64},
    {"UC_MODE_PPC32", UC_MODE_PPC32},
    {"UC_MODE_PPC64", UC_MODE_PPC64},
    {"UC_MODE_QPX", UC_MODE_QPX},
    {"UC_MODE_SPARC32", UC_MODE_SPARC32},
    {"UC_MODE_SPARC64", UC_MODE_SPARC64},
    {"UC_MODE_V9", UC_MODE_V9},

    {"UC_ERR_OK", UC_ERR_OK},
    {"UC_ERR_NOMEM", UC_ERR_NOMEM},
    {"UC_ERR_ARCH", UC_ERR_ARCH},
    {"UC_ERR_HANDLE", UC_ERR_HANDLE},
    {"UC_ERR_MODE", UC_ERR_MODE},
    {"UC_ERR_VERSION", UC_ERR_VERSION},
    {"UC_ERR_READ_UNMAPPED", UC_ERR_READ_UNMAPPED},
    {"UC_ERR_WRITE_UNMAPPED", UC_ERR_WRITE_UNMAPPED},
    {"UC_ERR_FETCH_UNMAPPED", UC_ERR_FETCH_UNMAPPED},
    {"UC_ERR_HOOK", UC_ERR_HOOK},
    {"UC_ERR_INSN_INVALID", UC_ERR_INSN_INVALID},
    {"UC_ERR_MAP", UC_ERR_MAP},
    {"UC_ERR_WRITE_PROT", UC_ERR_WRITE_PROT},
    {"UC_ERR_READ_PROT", UC_ERR_READ_PROT},
    {"UC_ERR_FETCH_PROT", UC_ERR_FETCH_PROT},
    {"UC_ERR_ARG", UC_ERR_ARG},
    {"UC_ERR_READ_UNALIGNED", UC_ERR_READ_UNALIGNED},
    {"UC_ERR_WRITE_UNALIGNED", UC_ERR_WRITE_UNALIGNED},
    {"UC_ERR_FETCH_UNALIGNED", UC_ERR_FETCH_UNALIGNED},
    {"UC_ERR_HOOK_EXIST", UC_ERR_HOOK_EXIST},
    {"UC_ERR_RESOURCE", UC_ERR_RESOURCE},
    {"UC_ERR_EXCEPTION", UC_ERR_EXCEPTION},

    {"UC_MEM_READ", UC_MEM_READ},
    {"UC_MEM_WRITE", UC_MEM_WRITE},
    {"UC_MEM_FETCH", UC_MEM_FETCH},
    {"UC_MEM_READ_UNMAPPED", UC_MEM_READ_UNMAPPED},
    {"UC_MEM_WRITE_UNMAPPED", UC_MEM_WRITE_UNMAPPED},
    {"UC_MEM_FETCH_UNMAPPED", UC_MEM_FETCH_UNMAPPED},
    {"UC_MEM_WRITE_PROT", UC_MEM_WRITE_PROT},
    {"UC_MEM_READ_PROT", UC_MEM_READ_PROT},
    {"UC_MEM_FETCH_PROT", UC_MEM_FETCH_PROT},
    {"UC_MEM_READ_AFTER", UC_MEM_READ_AFTER},

    {"UC_HOOK_INTR", UC_HOOK_INTR},
    {"UC_HOOK_INSN", UC_HOOK_INSN},
    {"UC_HOOK_CODE", UC_HOOK_CODE},
    {"UC_HOOK_BLOCK", UC_HOOK_BLOCK},
    {"UC_HOOK_MEM_READ_UNMAPPED", UC_HOOK_MEM_READ_UNMAPPED},
    {"UC_HOOK_MEM_WRITE_UNMAPPED", UC_HOOK_MEM_WRITE_UNMAPPED},
    {"UC_HOOK_MEM_FETCH_UNMAPPED", UC_HOOK_MEM_FETCH_UNMAPPED},
    {"UC_HOOK_MEM_READ_PROT", UC_HOOK_MEM_READ_PROT},
    {"UC_HOOK_MEM_WRITE_PROT", UC_HOOK_MEM_WRITE_PROT},
    {"UC_HOOK_MEM_FETCH_PROT", UC_HOOK_MEM_FETCH_PROT},
    {"UC_HOOK_MEM_READ", UC_HOOK_MEM_READ},
    {"UC_HOOK_MEM_WRITE", UC_HOOK_MEM_WRITE},
    {"UC_HOOK_MEM_FETCH", UC_HOOK_MEM_FETCH},
    {"UC_HOOK_MEM_READ_AFTER", UC_HOOK_MEM_READ_AFTER},

    {"UC_HOOK_MEM_UNMAPPED", UC_HOOK_MEM_UNMAPPED},
    {"UC_HOOK_MEM_PROT", UC_HOOK_MEM_PROT},
    {"UC_HOOK_MEM_READ_INVALID", UC_HOOK_MEM_READ_INVALID},
    {"UC_HOOK_MEM_WRITE_INVALID", UC_HOOK_MEM_WRITE_INVALID},
    {"UC_HOOK_MEM_FETCH_INVALID", UC_HOOK_MEM_FETCH_INVALID},
    {"UC_HOOK_MEM_INVALID", UC_HOOK_MEM_INVALID},
    {"UC_HOOK_MEM_VALID", UC_HOOK_MEM_VALID},

    {"UC_QUERY_MODE", UC_QUERY_MODE},
    {"UC_QUERY_PAGE_SIZE", UC_QUERY_PAGE_SIZE},

#ifdef UC_QUERY_ARCH
    {"UC_QUERY_ARCH", UC_QUERY_ARCH},
#endif

    {"UC_PROT_NONE", UC_PROT_NONE},
    {"UC_PROT_READ", UC_PROT_READ},
    {"UC_PROT_WRITE", UC_PROT_WRITE},
    {"UC_PROT_EXEC", UC_PROT_EXEC},
    {"UC_PROT_ALL", UC_PROT_ALL},

    {nullptr, 0}
};


extern "C" UNICORN_EXPORT int luaopen_unicorn__clib(lua_State *L) {
    ul_init_engines_lib(L);

    luaL_newmetatable(L, kContextMetatableName);
    luaL_setfuncs(L, kContextMetamethods, 0);

    luaL_newlib(L, kUnicornLibraryFunctions);
    load_int_constants(L, kModuleConstants);
    return 1;
}
