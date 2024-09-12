-- Copyright (C) 2017-2024 by Diego Argueta
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

local unicorn = require 'unicorn'
local uc_const = require 'unicorn.unicorn_const'
local x86 = require 'unicorn.x86_const'


describe('[x86] Signedness tests  #int64only', function ()
  -- While this behavior is undesirable, we do need to test it to ensure
  -- compatibility with client code until we fix it.
  it('Returns 2^64 - 1 as -1', function ()
    local uc = unicorn.open(uc_const.UC_ARCH_X86, uc_const.UC_MODE_64)
    uc:reg_write(x86.UC_X86_REG_RAX, 0xffffffffffffffff)
    assert.are.equals(-1, uc:reg_read(x86.UC_X86_REG_RAX))
  end)

  it('Returns 2^63 - 1 as 0x7fffffffffffffff', function ()
    local uc = unicorn.open(uc_const.UC_ARCH_X86, uc_const.UC_MODE_64)
    uc:reg_write(x86.UC_X86_REG_RAX, 0x7fffffffffffffff)
    assert.are.equals(0x7fffffffffffffff, uc:reg_read(x86.UC_X86_REG_RAX))
  end)

  it('Returns 2^63 - 1 as 0x7fffffffffffffff (string)', function ()
    local uc = unicorn.open(uc_const.UC_ARCH_X86, uc_const.UC_MODE_64)
    uc:reg_write(x86.UC_X86_REG_RAX, '0x7fffffffffffffff')
    assert.are.equals(0x7fffffffffffffff, uc:reg_read(x86.UC_X86_REG_RAX))
  end)

  it('Accepts negative values and returns them properly', function ()
    local uc = unicorn.open(uc_const.UC_ARCH_X86, uc_const.UC_MODE_64)
    uc:reg_write(x86.UC_X86_REG_RAX, -17480)
    assert.are.equals(-17480, uc:reg_read(x86.UC_X86_REG_RAX))
  end)
end)
