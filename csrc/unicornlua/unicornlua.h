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
 * The primary Unicorn Lua header needed by all C code using the library.
 *
 * @file unicornlua.h
 */

#pragma once

#include <lua.h>
#include <unicorn/unicorn.h>


/**
 * The major version number of this Lua library (first part, 1.x.x).
 */
#define UNICORNLUA_VERSION_MAJOR 2

/**
 * The minor version number of this Lua library (second part, x.1.x).
 */
#define UNICORNLUA_VERSION_MINOR 2

/**
 * The patch version number of this Lua library (third part, x.x.1).
 */
#define UNICORNLUA_VERSION_PATCH 1

/**
 * Create a 24-bit number from a release's major, minor, and patch numbers.
 *
 * You can use this for comparing a version number in your C/C++ code:
 *
 *      #if UNICORNLUA_VERSION < MAKE_VERSION(1, 1, 0)
 *          // Executes on versions below 1.1.0
 *      #else
 *          // Executes on versions 1.1.0 and above (including 1.1.1)
 *      #endif
 */
#define MAKE_VERSION(major, minor, patch) (((major) << 16) | ((minor) << 8) | (patch))

/**
 * The full version number of this Lua library, as an integer.
 *
 * This is a 24-bit number, where each version component is bit-shifted so that
 * it occupies a single byte. The major version is the most-significant 8 bits,
 * the minor version is the 8 bits below that, and the patch number is below
 * that. Thus, release 1.10.16 would be represented by 0x010A10.
 */
#define UNICORNLUA_VERSION                                                               \
    MAKE_VERSION(UNICORNLUA_VERSION_MAJOR, UNICORNLUA_VERSION_MINOR,                     \
                 UNICORNLUA_VERSION_PATCH)

/**
 * The full version number of the Unicorn library this was compiled with, as an
 * integer.
 *
 * The construction and semantics of this version number are the same as in
 * @ref UNICORNLUA_VERSION.
 */
#define UNICORNLUA_UNICORN_MAJOR_MINOR_PATCH                                             \
    MAKE_VERSION(UC_VERSION_MAJOR, UC_VERSION_MINOR, UC_VERSION_EXTRA)
