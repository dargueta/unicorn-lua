/**
 * The primary Unicorn Lua header needed by all C code using the library.
 *
 * @file unicornlua.h
 */

#pragma once

#include <unicorn/unicorn.h>

#include "unicornlua/compat.h"
#include "unicornlua/lua.h"

#if UC_VERSION_MAJOR != 1
#error "Library must be compiled against version 1.x of Unicorn."
#endif

/**
 * The major version number of this Lua library (first part, 1.x.x).
 */
#define UNICORNLUA_VERSION_MAJOR 2

/**
 * The minor version number of this Lua library (second part, x.1.x).
 */
#define UNICORNLUA_VERSION_MINOR 1

/**
 * The patch version number of this Lua library (third part, x.x.1).
 */
#define UNICORNLUA_VERSION_PATCH 0

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
#define UNICORNLUA_VERSION MAKE_VERSION(UNICORNLUA_VERSION_MAJOR, \
    UNICORNLUA_VERSION_MINOR,                                     \
    UNICORNLUA_VERSION_PATCH)

/**
 * The full version number of the Unicorn library this was compiled with, as an integer.
 *
 * The construction and semantics of this version number are the same as in
 * @ref UNICORNLUA_VERSION.
 */
#define UNICORNLUA_UNICORN_MAJOR_MINOR_PATCH MAKE_VERSION(UC_VERSION_MAJOR, \
    UC_VERSION_MINOR,                                                       \
    UC_VERSION_EXTRA)
