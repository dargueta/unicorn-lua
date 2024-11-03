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
 * Lua bindings for Unicorn register operations.
 *
 * @file registers.h
 */

#pragma once

#include "register_types.h"
#include <float.h>
#include <lua.h>
#include <stdint.h>

#if FLT_RADIX != 2
#    error "Can't handle floating-point radixes other than 2 right now."
#endif

#if FLT_MANT_DIG == 24
typedef float uclua_float32;
#else
#    error "`float` isn't 32 bits. This library can't handle that yet."
#endif

#if DBL_MANT_DIG == 53
typedef double uclua_float64;
#else
#    error "`double` isn't 64 bits. This library can't handle that yet."
#endif

#if defined(__GNUC__) && defined(__x86__) && defined(USE_FLOAT128)
#    define UCLUA_HAVE_GNUFLOAT128
#endif

#if defined(LDBL_MANT_DIG)
typedef long double uclua_float80;

#    if LDBL_MANT_DIG == 64
// `long double` is 80 bits on this platform.
#        define UCLUA_FLOAT80_SIZE 80
#    elif LDBL_MANT_DIG == 113
// `long double` is 128 bits on this platform.
#        define UCLUA_FLOAT80_SIZE 128
#    else
// No idea how big a `long double` is but it's biiiig.
#        define UCLUA_FLOAT80_SIZE 0
#    endif
#elif defined(UCLUA_HAVE_GNUFLOAT128)
// Platform doesn't support `long double` but does support __float128.
#    define UCLUA_FLOAT80_SIZE 128
typedef __float128 uclua_float80;
#else
#    error "Platform has no way to represent 80-bit floating-point registers."
#endif

/**
 * Define a buffer large enough to hold the largest registers available.
 *
 * We need 64 bytes to be able to hold a 512-bit ZMM register. For now, only the
 * low 32 or 64 bits are accessible to Lua. Eventually we'll figure out how to
 * use the rest.
 */
typedef uint8_t register_buffer_type[64];

struct Register
{
    register_buffer_type data;
    enum RegisterDataType kind;
};

/**
 * Write to an architecture register.
 */
int ul_reg_write(lua_State *L);
int ul_reg_read(lua_State *L);
int ul_reg_write_batch(lua_State *L);
int ul_reg_read_batch(lua_State *L);

/**
 * Read a register from the processor, as something other than as a plain
 * integer.
 *
 * You'll need to use this for reading registers that aren't integers, or for
 * SSE/AVX/AVX-512 registers that can act as arrays of values.
 */
int ul_reg_read_as(lua_State *L);

/**
 * Like @ref ul_reg_read_as, but reads multiple registers at once.
 *
 * The argument to the Lua function is a table mapping the ID of the register to
 * read to the format it should be read in.
 */
int ul_reg_read_batch_as(lua_State *L);

/**
 * Write to a processor register as something other than as a plain integer.
 *
 * You'll need to use this for writing registers that aren't integers, or for
 * SSE/AVX/AVX-512 registers that can act as arrays of values.
 */
int ul_reg_write_as(lua_State *L);

/**
 * Read an x87 floating-point number as the host machine's native format.
 *
 * @warning There's no way to represent a signaling or "indefinite" NaN in C++.
 * Both of these values are returned as std::NAN.
 */
lua_Number read_float80(const uint8_t *data);

/**
 * Store a floating-point value into an x87 floating-point number.
 *
 * @param value     The floating-point value to store as an 80-bit x86 float.
 * @param buffer    The buffer to store the serialized float into. Must hold at
 *                  least 10 bytes.
 *
 * @warning No distinction is made between quiet and signaling NaNs. All NaNs
 * are stored in memory as a quiet NaN.
 */
void write_float80(lua_Number value, uint8_t *buffer);

void register__assign_value(register_buffer_type reg, const void *buffer,
                            enum RegisterDataType kind);
