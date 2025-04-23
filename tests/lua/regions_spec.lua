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

-- Tests for listing memory regions
local unicorn = require 'unicorn'
local uc_const = require 'unicorn.unicorn_const'


describe('Memory regions', function ()
  it('Returns an empty table when no memory is mapped in', function ()
    local uc = unicorn.open(uc_const.UC_ARCH_X86, uc_const.UC_MODE_64)
    local regions = uc:mem_regions()

    assert.is_truthy(regions)
    assert.are.equals(0, #regions)
    uc:close()
  end)

  it('Handles one region', function ()
    local uc = unicorn.open(uc_const.UC_ARCH_X86, uc_const.UC_MODE_64)
    uc:mem_map(0, 0x100000, uc_const.UC_PROT_ALL)

    local regions = uc:mem_regions()
    assert.are.equals(1, #regions, 'Wrong number of regions.')

    local region = regions[1]
    assert.are.equals(region.begins, 0)
    assert.are.equals(region.ends, 0xfffff)
    assert.are.equals(region.perms, uc_const.UC_PROT_ALL)
    uc:close()
  end)

  it('Handles multiple regions', function ()
    local uc = unicorn.open(uc_const.UC_ARCH_X86, uc_const.UC_MODE_64)
    uc:mem_map(0, 0x100000, uc_const.UC_PROT_ALL)
    uc:mem_map(0x200000, 0x1000, uc_const.UC_PROT_EXEC)

    local regions = uc:mem_regions()
    assert.are.equals(2, #regions, 'Wrong number of regions.')

    assert.are.equals(regions[1].begins, 0)
    assert.are.equals(regions[1].ends, 0xfffff)
    assert.are.equals(regions[1].perms, uc_const.UC_PROT_ALL)

    assert.are.equals(regions[2].begins, 0x200000)
    assert.are.equals(regions[2].ends, 0x200fff)
    assert.are.equals(regions[2].perms, uc_const.UC_PROT_EXEC)
    uc:close()
  end)
end)
