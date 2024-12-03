// Copyright (C) 2017-2024 by Diego Argueta
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

/**
 * Miscellaneous utilities used by the Unicorn Lua binding.
 *
 * @file utils.h
 */

#pragma once

#include <lauxlib.h>
#include <lua.h>
#include <stdarg.h>
#include <stdnoreturn.h>
#include <unicorn/unicorn.h>

#define UL_MAX_ERROR_MESSAGE_LENGTH 1024

#if __STDC_VERSION__ >= 202311L
#    define UL_FALLTHROUGH_MARKER [[fallthrough]]
#    define UL_RETURNS_POINTER [[nodiscard]]
#    define UL_UNREACHABLE_MARKER unreachable()
#    define UL_PUBLIC_API
#    define UL_PRIVATE
#elif defined(__GNUC__)
// GCC, Clang, ICC
#    define UL_FALLTHROUGH_MARKER __attribute__((fallthrough))
#    define UL_RETURNS_POINTER __attribute__((returns_nonnull, warn_unused_result))
#    define UL_UNREACHABLE_MARKER __builtin_unreachable()
#    define UL_PUBLIC_API __attribute__((visibility("default")))
#    define UL_PRIVATE __attribute__((visibility("internal")))
#elif defined(_MSC_VER)
// Microsoft Visual Studio
#    define UL_FALLTHROUGH_MARKER
#    define UL_RETURNS_POINTER _Must_inspect_result_
#    define UL_UNREACHABLE_MARKER __assume(false)
#    define UL_PUBLIC_API __declspec(dllexport)
#    define UL_PRIVATE
#else
#    define UL_FALLTHROUGH_MARKER
#    define UL_RETURNS_POINTER
#    define UL_UNREACHABLE_MARKER
#    define UL_PUBLIC_API
#    define UL_PRIVATE
#endif

/**
 * Use snprintf to build a string and push it onto the Lua stack.
 *
 * Lua's string formatter is highly limited in the format specifiers it supports, so if we
 * want to do anything beyond that, we need to derive our own method. The final string is
 * pushed onto the Lua stack.
 *
 * @param L  The Lua state.
 * @param max_size  The maximum size of the final string, excluding the terminating null.
 *                  The generated string will always fit this size.
 * @param format  The format string.
 * @param argv  An initialized varargs list pointing to the first argument of the format
 *              string.
 */
UL_PRIVATE void ulinternal_vsnprintf(lua_State *L, size_t max_size, const char *format,
                                     va_list argv);

UL_PRIVATE _Noreturn int ulinternal_crash_not_implemented(lua_State *L);

UL_PRIVATE _Noreturn int ulinternal_crash_unsupported_operation(lua_State *L);

/**
 * Call `luaL_error` if and only if @a error is not @ref UC_ERR_OK.
 *
 * @param L         A pointer to the current Lua state.
 * @param error     A unicorn error code.
 * @param context   Extra information to include as the first part of the error message.
 */
#ifdef __GNUC__
__attribute__((format(printf, 3, 4)))
#endif
UL_PRIVATE void
ulinternal_crash_if_failed(lua_State *L, uc_err code, const char *format, ...);

/**
 * Call `luaL_error` with a string created using the C standard sprintf().
 *
 * @param L  The Lua state.
 * @param format
 *      The format string for the error message. This uses sprintf(), not Lua's formatter,
 *      so the full standard library's capabilities can be used. The final error message
 *      is truncated to @ref UL_MAX_ERROR_MESSAGE_LENGTH characters.
 * @param ...
 */
#ifdef __GNUC__
__attribute__((format(printf, 2, 3)))
#endif
UL_PRIVATE _Noreturn void
ulinternal_crash(lua_State *L, const char *format, ...);
