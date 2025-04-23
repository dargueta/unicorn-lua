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

-- Adapted directly from the Python tutorial on the Unicorn Engine's website.

describe('[x86] Basic register read/write', function ()
  it('Tutorial from website', function ()
    local unicorn = require 'unicorn'
    local uc_const = require 'unicorn.unicorn_const'
    local x86 = require 'unicorn.x86_const'

    local X86_CODE32 = "\065\074" -- INC ecx; DEC edx
    local ADDRESS = 0x1000000

    -- Initialize emulator in X86-32bit mode
    local mu = unicorn.open(uc_const.UC_ARCH_X86, uc_const.UC_MODE_32)

    -- map 2MB memory for this emulation
    mu:mem_map(ADDRESS, 2 ^ 21)

    -- write machine code to be emulated to memory
    mu:mem_write(ADDRESS, X86_CODE32)

    -- initialize machine registers
    mu:reg_write(x86.UC_X86_REG_ECX, 0x1234)
    mu:reg_write(x86.UC_X86_REG_EDX, 0x7890)

    -- emulate code in infinite time & unlimited instructions
    mu:emu_start(ADDRESS, ADDRESS + #X86_CODE32)

    -- read some registers back
    local r_ecx = mu:reg_read(x86.UC_X86_REG_ECX)
    local r_edx = mu:reg_read(x86.UC_X86_REG_EDX)

    -- make sure we got the right values
    assert.are.equals(0x1235, r_ecx)
    assert.are.equals(0x788f, r_edx)
    mu:close()
  end)
end)
