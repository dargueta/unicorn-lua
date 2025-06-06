-- Copyright (C) 2017-2025 by Diego Argueta
--
-- This program is free software; you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation; either version 2 of the License, or
-- (at your option) any later version.
--
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
--
-- You should have received a copy of the GNU General Public License along
-- with this program; if not, write to the Free Software Foundation, Inc.,
-- 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

--- The main module for the Unicorn CPU Emulator.
---
--- @author Diego Argueta
--- @copyright 2017-2025 Diego Argueta
--- @license GPL-2
--- @release 2.3.0
--- @module unicorn

local uc_c = require("unicorn_c_")
local uc_engine = require("unicorn.engine")

local M = {
    -- The major, minor, and patch numbers of this Lua library's version.
    --
    -- To get the version of the Unicorn C library this binding wraps around, see
    -- @{unicorn.version}.
    LUA_LIBRARY_VERSION = {2, 3, 0},

    --- Determine if `architecture` is supported by the underlying Unicorn library.
    ---
    --- @tparam int architecture  An enum value indicating the architecture, from
    --- @{unicorn_const}. These all start with `UC_ARCH_`, e.g.
    --- @{unicorn_const.UC_ARCH_X86}.
    ---
    --- @treturn bool  A boolean indicating if Unicorn supports the given architecture.
    ---
    --- @function arch_supported
    --- @usage unicorn.arch_supported(unicorn_const.UC_ARCH_ARM64)
    arch_supported = uc_c.arch_supported,

    --- Return the error message corresponding to the given Unicorn error code.
    ---
    --- @tparam int code  An error code as returned from one of the API functions.
    --- @treturn string   A standard error message describing the code.
    ---
    --- @function strerror
    strerror = uc_c.strerror,

    --- Return two values, the major and minor version numbers of the underlying Unicorn
    --- Engine C library.
    ---
    --- @treturn int,int The major and minor version of the library, respectively.
    --- @function version
    version = uc_c.version,
}


--- Create a new Unicorn engine.
---
--- @tparam int architecture  An enum value indicating which architecture to emulate. The
--- constants are available in @{unicorn_const} and all start with `UC_ARCH_`.
--- @tparam int mode_flags  Flags providing broad details of the CPU's operating mode.
--- For example, these can be used to choose between starting an x86 CPU in 16-, 32-, or
--- 64-bit mode, or selecting the endianness on bi-endian architectures. These flags are
--- available in @{unicorn_const} and all start with `UC_MODE_`.
---
--- @treturn Engine  An initialized @{engine.Engine}.
---
--- @usage local engine = unicorn.open(unicorn_const.UC_ARCH_X86, unicorn_const.UC_MODE_32)
function M.open(architecture, mode_flags)
    local handle = uc_c.open(architecture, mode_flags or 0)
    return uc_engine.wrap_handle_(handle)
end

return M
