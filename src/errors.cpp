#include <stdexcept>

#include <unicorn/unicorn.h>

#include "unicornlua/errors.hpp"
#include "unicornlua/lua.hpp"

UnicornLibraryError::UnicornLibraryError(uc_err error)
    : std::runtime_error(uc_strerror(error))
    , error_(error)
{
}

uc_err UnicornLibraryError::get_error() const noexcept { return error_; }

void UnicornLibraryError::rethrow_as_lua_error(lua_State* L)
{
    luaL_error(L, what());
}

LuaBindingError::LuaBindingError(const char* message)
    : std::runtime_error(message)
{
}

void LuaBindingError::rethrow_as_lua_error(lua_State* L)
{
    luaL_error(L, what());
}
